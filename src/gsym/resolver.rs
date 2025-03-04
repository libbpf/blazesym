use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem;
use std::mem::swap;
use std::path::Path;
use std::path::PathBuf;

use crate::log::warn;
use crate::mmap::Mmap;
use crate::symbolize::CodeInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::InlinedFn;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::IntoError as _;
use crate::Result;

use super::inline::InlineInfo;
use super::linetab::run_op;
use super::linetab::LineTableHeader;
use super::linetab::LineTableRow;
use super::linetab::RunResult;
use super::parser::parse_address_data;
use super::parser::GsymContext;
use super::types::AddrInfo;
use super::types::INFO_TYPE_INLINE_INFO;
use super::types::INFO_TYPE_LINE_TABLE_INFO;


#[allow(dead_code)]
enum Data<'dat> {
    Mmap(Mmap),
    Slice(&'dat [u8]),
}


/// A symbol resolver for the GSYM format.
pub(crate) struct GsymResolver<'dat> {
    file_name: Option<PathBuf>,
    // SAFETY: This member should be listed before `ctx` to make sure we never
    //         end up with dangling references.
    _data: Data<'dat>,
    ctx: GsymContext<'dat>,
}

impl GsymResolver<'static> {
    /// Create a `GsymResolver` that loads data from the provided file.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let mmap = Mmap::builder().open(path)?;
        Self::from_mmap(path.to_path_buf(), mmap)
    }

    pub(crate) fn from_file(path: PathBuf, file: &File) -> Result<Self> {
        let mmap = Mmap::map(file)?;
        Self::from_mmap(path, mmap)
    }

    fn from_mmap(path: PathBuf, mmap: Mmap) -> Result<Self> {
        let ctx = GsymContext::parse_header(&mmap)?;
        let slf = Self {
            file_name: Some(path),
            // SAFETY: We own the underlying `Mmap` object and never hand out
            //         any 'static references to its data. So it is safe for us
            //         to transmute the lifetime.
            ctx: unsafe { mem::transmute::<GsymContext<'_>, GsymContext<'static>>(ctx) },
            _data: Data::Mmap(mmap),
        };

        Ok(slf)
    }
}

impl<'dat> GsymResolver<'dat> {
    /// Create a `GsymResolver` that works on the provided "raw" Gsym data.
    pub(crate) fn with_data(data: &'dat [u8]) -> Result<Self> {
        let ctx = GsymContext::parse_header(data)?;
        let slf = Self {
            file_name: None,
            ctx,
            _data: Data::Slice(data),
        };

        Ok(slf)
    }

    fn query_frame_code_info(&self, file_idx: u32, line: Option<u32>) -> Result<CodeInfo<'_>> {
        let finfo = self
            .ctx
            .file_info(file_idx as usize)
            .ok_or_invalid_data(|| format!("failed to retrieve file info data @ {}", file_idx))?;
        let dir = self
            .ctx
            .get_str(finfo.directory as usize)
            .ok_or_invalid_data(|| {
                format!("failed to retrieve directory string @ {}", finfo.directory)
            })?;
        let file = self
            .ctx
            .get_str(finfo.filename as usize)
            .ok_or_invalid_data(|| {
                format!("failed to retrieve file name string @ {}", finfo.filename)
            })?;

        let info = CodeInfo {
            dir: Some(Cow::Borrowed(Path::new(dir))),
            file: Cow::Borrowed(OsStr::new(file)),
            line,
            column: None,
            _non_exhaustive: (),
        };
        Ok(info)
    }

    fn parse_line_tab_info(
        &self,
        mut data: &[u8],
        symaddr: Addr,
        addr: Addr,
    ) -> Result<Option<LineTableRow>> {
        // Continue to execute all GSYM line table operations
        // until the end of the buffer is reached or a row
        // containing addr is located.
        let lntab_hdr = LineTableHeader::parse(&mut data)
            .ok_or_invalid_data(|| "failed to parse line table header")?;
        let mut lntab_row = LineTableRow::from_header(&lntab_hdr, symaddr);
        let mut last_lntab_row = lntab_row.clone();
        let mut row_cnt = 0;
        while !data.is_empty() {
            match run_op(&mut lntab_row, &lntab_hdr, &mut data) {
                Some(RunResult::Ok) => {}
                Some(RunResult::NewRow) => {
                    row_cnt += 1;
                    if addr < lntab_row.addr {
                        if row_cnt == 1 {
                            // The address is lower than the first row.
                            return Ok(None)
                        }
                        // Rollback to the last row.
                        lntab_row = last_lntab_row;
                        break
                    }
                    last_lntab_row = lntab_row.clone();
                }
                Some(RunResult::End) | None => break,
            }
        }

        if row_cnt == 0 {
            return Ok(None)
        }
        Ok(Some(lntab_row))
    }
}

impl Symbolize for GsymResolver<'_> {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        if let Some(idx) = self.ctx.find_addr(addr) {
            let sym_addr = self
                .ctx
                .addr_at(idx)
                .ok_or_invalid_data(|| format!("failed to read address table entry {idx}"))?;
            if addr < sym_addr {
                return Ok(Err(Reason::UnknownAddr))
            }

            let info = self
                .ctx
                .addr_info(idx)
                .ok_or_invalid_data(|| format!("failed to read address information entry {idx}"))?;
            // NB: Never bail out for zero sized symbols. We have seen cases
            //     where the reported `sym_addr` was (way) before `addr` for
            //     zero sized symbols, but the majority of tools report the
            //     result irrespectively and the behavior was deemed the right
            //     call.
            if info.size > 0 && addr >= (sym_addr + info.size as Addr) {
                return Ok(Err(Reason::UnknownAddr))
            }

            let name = self
                .ctx
                .get_str(info.name as usize)
                .and_then(|s| s.to_str())
                .ok_or_invalid_data(|| {
                    format!("failed to read string table entry at offset {}", info.name)
                })?;
            // Gsym does not carry any source code language information.
            let lang = SrcLang::Unknown;
            let mut sym = ResolvedSym {
                name,
                // TODO: Double check if there is module information in
                //       a Gsym file.
                module: None,
                addr: sym_addr,
                size: Some(usize::try_from(info.size).unwrap_or(usize::MAX)),
                lang,
                code_info: None,
                inlined: Box::new([]),
            };
            let () = self.fill_code_info(&mut sym, addr, opts, sym_addr, &info)?;

            Ok(Ok(sym))
        } else {
            Ok(Err(Reason::UnknownAddr))
        }
    }
}

impl GsymResolver<'_> {
    fn fill_code_info<'slf>(
        &'slf self,
        sym: &mut ResolvedSym<'slf>,
        addr: Addr,
        opts: &FindSymOpts,
        sym_addr: Addr,
        info: &AddrInfo,
    ) -> Result<()> {
        if !opts.code_info() {
            return Ok(())
        }

        let mut line_tab_info = None;
        let mut inline_info = None;
        let addrdatas = parse_address_data(info.data);
        for addr_ent in addrdatas {
            match addr_ent.typ {
                INFO_TYPE_LINE_TABLE_INFO => {
                    if line_tab_info.is_none() {
                        line_tab_info = self.parse_line_tab_info(addr_ent.data, sym_addr, addr)?;
                    }
                }
                INFO_TYPE_INLINE_INFO if opts.inlined_fns() => {
                    if inline_info.is_none() {
                        let mut data = addr_ent.data;
                        inline_info = InlineInfo::parse(&mut data, sym_addr, Some(addr))?;
                    }
                }
                typ => {
                    warn!("encountered unknown info type: {typ}; ignoring...");
                    continue
                }
            }
        }

        let mut line_tab_info = if let Some(line_tab_row) = line_tab_info {
            self.query_frame_code_info(line_tab_row.file_idx, Some(line_tab_row.file_line))?
        } else {
            return Ok(())
        };

        let mut inlined = Vec::<InlinedFn>::new();

        if let Some(inline_info) = inline_info {
            let mut inline_stack = inline_info.inline_stack(addr).into_iter();
            // As per Gsym file format, the first "frame" only contains the
            // name and it effectively is meant to overwrite what is already
            // contained in the line table.
            if let Some(inline_info) = inline_stack.next() {
                sym.name = self
                    .ctx
                    .get_str(inline_info.name as usize)
                    .and_then(|s| s.to_str())
                    .ok_or_invalid_data(|| {
                        format!(
                            "failed to read string table entry at offset {}",
                            inline_info.name
                        )
                    })?;

                let () = inlined.reserve(inline_stack.len());

                for frame in inline_stack {
                    let name = self
                        .ctx
                        .get_str(frame.name as usize)
                        .and_then(|s| s.to_str())
                        .ok_or_invalid_data(|| {
                            format!("failed to read string table entry at offset {}", frame.name)
                        })?;

                    let mut code_info = if let Some(file) = frame.call_file {
                        let code_info = self.query_frame_code_info(file, frame.call_line)?;
                        Some(code_info)
                    } else {
                        None
                    };

                    // For each frame we need to move the code information
                    // up by one layer.
                    if let Some(ref mut last_code_info) =
                        inlined.last_mut().map(|f| &mut f.code_info)
                    {
                        let () = swap(&mut code_info, last_code_info);
                    } else if let Some(code_info) = &mut code_info {
                        let () = swap(code_info, &mut line_tab_info);
                    }

                    let inlined_fn = InlinedFn {
                        name: Cow::Borrowed(name),
                        code_info,
                        _non_exhaustive: (),
                    };
                    let () = inlined.push(inlined_fn);
                }
            }
        }

        sym.code_info = Some(line_tab_info);
        sym.inlined = inlined.into_boxed_slice();

        Ok(())
    }
}

impl Debug for GsymResolver<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let path = self
            .file_name
            .as_deref()
            .unwrap_or_else(|| Path::new("<unknown-file>"));
        write!(f, "GSYM {}", path.display())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::read as read_file;

    use test_log::test;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");

        let resolver = GsymResolver::open(test_gsym).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("GSYM"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addrs.gsym"), "{dbg}");
    }

    /// Check that we can create a `GsymResolver` using a "raw" slice of data.
    #[test]
    fn creation_from_raw_data() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");
        let data = read_file(test_gsym).unwrap();

        let resolver = GsymResolver::with_data(&data).unwrap();
        assert_eq!(resolver.file_name, None);
    }

    /// Make sure that we can find file line information for a function, if
    /// available.
    #[test]
    fn find_line_info() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");
        let resolver = GsymResolver::open(test_gsym).unwrap();

        // `main` resides at address 0x2000000, and it's located at the given
        // line.
        let sym = resolver
            .find_sym(0x2000000, &FindSymOpts::CodeInfoAndInlined)
            .unwrap()
            .unwrap();
        assert_eq!(sym.name, "main");
        assert!(sym.inlined.is_empty());

        let info = sym.code_info.unwrap();
        assert_eq!(info.line, Some(75));
        assert_eq!(info.file, OsStr::new("test-stable-addrs.c"));

        // `factorial` resides at address 0x2000200, and it's located at the
        // given line.
        let sym = resolver
            .find_sym(0x2000200, &FindSymOpts::CodeInfoAndInlined)
            .unwrap()
            .unwrap();
        assert_eq!(sym.name, "factorial");
        assert!(sym.inlined.is_empty());

        let info = sym.code_info.unwrap();
        assert_eq!(info.line, Some(10));
        assert_eq!(info.file, OsStr::new("test-stable-addrs.c"));

        // Address is hopefully sufficiently far into `factorial_inline_test` to
        // always fall into the inlined region, no matter toolchain. If not, add
        // padding bytes/dummy instructions and adjust some more.
        let addr = 0x200030a;
        let sym = resolver
            .find_sym(addr, &FindSymOpts::CodeInfoAndInlined)
            .unwrap()
            .unwrap();
        assert_eq!(sym.name, "factorial_inline_test");
        assert_eq!(sym.inlined.len(), 2);

        let info = sym.code_info.unwrap();
        assert_eq!(info.line, Some(34));
        assert_eq!(info.file, OsStr::new("test-stable-addrs.c"));

        let name = &sym.inlined[0].name;
        assert_eq!(*name, "factorial_inline_wrapper");
        let frame = sym.inlined[0].code_info.as_ref().unwrap();
        assert_eq!(frame.file, OsStr::new("test-stable-addrs.c"));
        assert_eq!(frame.line, Some(28));

        let name = &sym.inlined[1].name;
        assert_eq!(*name, "factorial_2nd_layer_inline_wrapper");
        let frame = sym.inlined[1].code_info.as_ref().unwrap();
        assert_eq!(frame.file, OsStr::new("test-stable-addrs.c"));
        assert_eq!(frame.line, Some(23));

        let sym = resolver
            .find_sym(addr, &FindSymOpts::CodeInfo)
            .unwrap()
            .unwrap();
        assert_eq!(sym.name, "factorial_inline_test");
        assert!(sym.inlined.is_empty());

        let info = sym.code_info.unwrap();
        // Note that the line number reported without inline information is
        // different to that when using inlined function information, because in
        // Gsym this additional data is used to "refine" the result.
        assert_eq!(info.line, Some(23));
        assert_eq!(info.file, OsStr::new("test-stable-addrs.c"));
    }
}

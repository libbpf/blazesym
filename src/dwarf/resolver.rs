use std::borrow::Cow;
#[cfg(test)]
use std::env;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem;
use std::mem::swap;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use gimli::AbbreviationsCacheStrategy;
use gimli::Dwarf;

use crate::elf::ElfParser;
#[cfg(test)]
use crate::elf::DEFAULT_DEBUG_DIRS;
use crate::error::IntoCowStr;
use crate::inspect::FindAddrOpts;
use crate::inspect::ForEachFn;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::log::debug;
use crate::log::warn;
use crate::symbolize::CodeInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::InlinedFn;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::Error;
use crate::ErrorExt;
use crate::Mmap;
use crate::Result;
use crate::SymType;

use super::debug_link::debug_link_crc32;
use super::debug_link::read_debug_link;
use super::debug_link::DebugFileIter;
use super::function::Function;
use super::location::Location;
use super::reader;
use super::unit::Unit;
use super::units::Units;


impl ErrorExt for gimli::Error {
    type Output = Error;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr,
    {
        Error::from(self).context(context)
    }

    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C,
    {
        Error::from(self).with_context(f)
    }
}


impl From<Option<gimli::DwLang>> for SrcLang {
    fn from(other: Option<gimli::DwLang>) -> Self {
        match other {
            Some(gimli::DW_LANG_Rust) => SrcLang::Rust,
            Some(
                gimli::DW_LANG_C_plus_plus
                | gimli::DW_LANG_C_plus_plus_03
                | gimli::DW_LANG_C_plus_plus_11
                | gimli::DW_LANG_C_plus_plus_14,
            ) => SrcLang::Cpp,
            _ => SrcLang::Unknown,
        }
    }
}


/// Find a debug file in a list of default directories.
///
/// `linker` is the path to the file containing the debug link. This function
/// searches a couple of "well-known" locations and then others constructed
/// based on the canonicalized path of `linker`.
///
/// # Notes
/// This function ignores any errors encountered.
fn find_debug_file(file: &OsStr, linker: Option<&Path>, debug_dirs: &[PathBuf]) -> Option<PathBuf> {
    let canonical_linker = linker.and_then(|linker| linker.canonicalize().ok());
    let it = DebugFileIter::new(debug_dirs, canonical_linker.as_deref(), file);

    for path in it {
        if path.exists() {
            debug!("found debug info at `{}`", path.display());
            return Some(path)
        }
    }
    warn!(
        "debug link references destination `{}` which was not found in any known location",
        Path::new(file).display(),
    );
    None
}


fn try_deref_debug_link(
    parser: &ElfParser,
    debug_dirs: &[PathBuf],
) -> Result<Option<Rc<ElfParser>>> {
    if let Some((file, checksum)) = read_debug_link(parser)? {
        match find_debug_file(file, parser.path(), debug_dirs) {
            Some(path) => {
                let mmap = Mmap::builder().open(&path).with_context(|| {
                    format!("failed to open debug link destination `{}`", path.display())
                })?;
                let crc = debug_link_crc32(&mmap);
                if crc != checksum {
                    return Err(Error::with_invalid_data(format!(
                        "debug link destination `{}` checksum does not match \
                         expected one: {crc:x} (actual) != {checksum:x} (expected)",
                        path.display()
                    )))
                }

                let dst_parser = Rc::new(ElfParser::from_mmap(mmap, Some(path)));
                Ok(Some(dst_parser))
            }
            None => Ok(None),
        }
    } else {
        Ok(None)
    }
}


/// DwarfResolver provides abilities to query DWARF information of binaries.
pub(crate) struct DwarfResolver {
    /// The lazily parsed compilation units of the DWARF file.
    // SAFETY: We must not hand out references with a 'static lifetime to
    //         this member. Rather, they should never outlive `self`.
    //         Furthermore, this member has to be listed before `parser`
    //         and `linkee_parser` to make sure we never end up with a
    //         dangling reference.
    units: Units<'static>,
    parser: Rc<ElfParser>,
    /// If the source file contains a valid debug link, this parser
    /// represents it.
    linkee_parser: Option<Rc<ElfParser>>,
}

impl DwarfResolver {
    /// Retrieve the resolver's underlying `ElfParser`.
    pub(crate) fn parser(&self) -> &Rc<ElfParser> {
        &self.parser
    }

    pub(crate) fn from_parser(
        parser: Rc<ElfParser>,
        debug_dirs: &[PathBuf],
    ) -> Result<Self, Error> {
        let linkee_parser = try_deref_debug_link(&parser, debug_dirs)?;

        // SAFETY: We own the `ElfParser` and make sure that it stays
        //         around while the `Units` object uses it. As such, it
        //         is fine to conjure a 'static lifetime here.
        let static_parser = unsafe {
            mem::transmute::<&ElfParser, &'static ElfParser>(
                linkee_parser.as_ref().unwrap_or(&parser).deref(),
            )
        };
        let mut load_section = |section| reader::load_section(static_parser, section);
        let mut dwarf = Dwarf::load(&mut load_section)?;
        // Cache abbreviations (which will cause them to be
        // automatically reused across compilation units), which can
        // speed up parsing of debug information potentially
        // dramatically, depending on debug information layout and how
        // much effort the linker spent on optimizing it.
        let () = dwarf.populate_abbreviations_cache(AbbreviationsCacheStrategy::Duplicates);

        let units = Units::parse(dwarf)?;
        let slf = Self {
            units,
            parser,
            linkee_parser,
        };
        Ok(slf)
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    #[cfg(test)]
    pub(crate) fn open(filename: &Path) -> Result<Self> {
        let parser = ElfParser::open(filename)?;
        let debug_dirs = DEFAULT_DEBUG_DIRS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        Self::from_parser(Rc::new(parser), debug_dirs.as_slice())
    }

    /// Try converting a `Function` into a `SymInfo`.
    ///
    /// # Notes
    /// This method only returns `None` if `function` does not have the `name`
    /// attribute set.
    fn function_to_sym_info<'slf>(
        &'slf self,
        function: &'slf Function,
        offset_in_file: bool,
    ) -> Result<Option<SymInfo<'slf>>> {
        let name = if let Some(name) = function.name {
            name.to_string().unwrap()
        } else {
            return Ok(None)
        };
        let addr = function
            .range
            .as_ref()
            .map(|range| range.begin as Addr)
            .unwrap_or(0);
        let size = function
            .range
            .as_ref()
            .and_then(|range| range.end.checked_sub(range.begin))
            .map(|size| usize::try_from(size).unwrap_or(usize::MAX))
            .unwrap_or(0);
        let info = SymInfo {
            name: Cow::Borrowed(name),
            addr,
            size,
            sym_type: SymType::Function,
            file_offset: offset_in_file
                .then(|| self.parser.find_file_offset(addr))
                .transpose()?
                .flatten(),
            obj_file_name: self.parser.path().map(Cow::Borrowed),
        };
        Ok(Some(info))
    }
}

impl Symbolize for DwarfResolver {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        let data = self.units.find_function(addr)?;
        let mut sym = if let Some((function, unit)) = data {
            let name = function
                .name
                .map(|name| name.to_string())
                .transpose()?
                .unwrap_or("");
            let fn_addr = function.range.map(|range| range.begin).unwrap_or(0);
            let size = function
                .range
                .map(|range| usize::try_from(range.end - range.begin).unwrap_or(usize::MAX));
            ResolvedSym {
                name,
                addr: fn_addr,
                size,
                lang: unit.language().into(),
                code_info: None,
                inlined: Box::new([]),
            }
        } else {
            // Fall back to checking ELF for the symbol corresponding to
            // the address. This is to mimic behavior of various tools
            // (e.g., `addr2line`). Basically, what can happen is that a
            // symbol is not present in DWARF, but source code
            // information for the address actually is. By checking ELF
            // as a fall back we support cases where ELF *does* contain
            // symbol, and we amend its information with the source code
            // information from DWARF.
            let parser = self.linkee_parser.as_ref().unwrap_or(&self.parser).deref();
            match parser.find_sym(addr, opts)? {
                Ok(sym) => sym,
                Err(reason) => return Ok(Err(reason)),
            }
        };

        let () = self.units.fill_code_info(&mut sym, addr, opts, data)?;

        Ok(Ok(sym))
    }
}

impl Inspect for DwarfResolver {
    /// Find information about a symbol given its name.
    ///
    /// # Notes
    /// - lookup of variables is not currently supported
    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported("not implemented"))
        }

        let syms = self
            .units
            .find_name(name)
            .map(|result| {
                match result {
                    Ok(function) => {
                        // SANITY: We found the function by name, so it must have the
                        //         name attribute set. `function_to_sym_info`
                        //         only returns `None` if no name is present.
                        let info = self
                            .function_to_sym_info(function, opts.offset_in_file)?
                            .unwrap();
                        Ok(info)
                    }
                    Err(err) => Err(Error::from(err)),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        if syms.is_empty() {
            let parser = self.linkee_parser.as_ref().unwrap_or(&self.parser).deref();
            parser.find_addr(name, opts)
        } else {
            Ok(syms)
        }
    }

    fn for_each(&self, _opts: &FindAddrOpts, _f: &mut ForEachFn<'_>) -> Result<()> {
        // TODO: Implement this functionality.
        Err(Error::with_unsupported(
            "DWARF logic does not currently support symbol iteration",
        ))
    }
}

impl Debug for DwarfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(stringify!(DwarfResolver))
    }
}


// Conceptually this block belongs to the `DwarfResolver` type, but because it
// uses a `Units` object with 'static lifetime we have to impl on `Units`
// directly.
impl<'dwarf> Units<'dwarf> {
    /// Fill in source code information for an address to the provided
    /// `IntSym`.
    ///
    /// `addr` is a normalized address.
    fn fill_code_info<'slf>(
        &'slf self,
        sym: &mut ResolvedSym<'slf>,
        addr: Addr,
        opts: &FindSymOpts,
        data: Option<(&'slf Function<'dwarf>, &'slf Unit<'dwarf>)>,
    ) -> Result<()> {
        if !opts.code_info() {
            return Ok(())
        }

        let direct_location = if let Some(direct_location) = self.find_location(addr)? {
            direct_location
        } else {
            return Ok(())
        };

        let Location {
            dir,
            file,
            line,
            column,
        } = direct_location;

        let mut direct_code_info = CodeInfo {
            dir: Some(Cow::Borrowed(dir)),
            file: Cow::Borrowed(file),
            line,
            column: column.map(|col| col.try_into().unwrap_or(u16::MAX)),
            _non_exhaustive: (),
        };

        let inlined = if opts.inlined_fns() {
            if let Some((function, unit)) = data {
                if let Some(inline_stack) = self.find_inlined_functions(addr, function, unit)? {
                    let mut inlined = Vec::<InlinedFn>::with_capacity(inline_stack.len());
                    for result in inline_stack {
                        let (name, location) = result?;
                        let mut code_info = location.map(|location| {
                            let Location {
                                dir,
                                file,
                                line,
                                column,
                            } = location;

                            CodeInfo {
                                dir: Some(Cow::Borrowed(dir)),
                                file: Cow::Borrowed(file),
                                line,
                                column: column.map(|col| col.try_into().unwrap_or(u16::MAX)),
                                _non_exhaustive: (),
                            }
                        });

                        // For each frame we need to move the code information
                        // up by one layer.
                        if let Some(ref mut last_code_info) =
                            inlined.last_mut().map(|f| &mut f.code_info)
                        {
                            let () = swap(&mut code_info, last_code_info);
                        } else if let Some(code_info) = &mut code_info {
                            let () = swap(code_info, &mut direct_code_info);
                        }

                        let inlined_fn = InlinedFn {
                            name: Cow::Borrowed(name),
                            code_info,
                            _non_exhaustive: (),
                        };
                        let () = inlined.push(inlined_fn);
                    }
                    inlined
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        sym.code_info = Some(direct_code_info);
        sym.inlined = inlined.into_boxed_slice();

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env::current_exe;
    use std::ffi::OsStr;
    use std::ops::ControlFlow;
    use std::path::PathBuf;

    use test_log::test;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let bin_name = current_exe().unwrap();
        let resolver = DwarfResolver::open(&bin_name).unwrap();
        assert_ne!(format!("{resolver:?}"), "");
    }

    /// Check that we can convert a `gimli::Error` into our own error type.
    #[test]
    fn error_conversion() {
        let inner = gimli::Error::Io;
        let err = Result::<(), _>::Err(inner)
            .context("failed to read")
            .unwrap_err();
        assert_eq!(format!("{err:#}"), format!("failed to read: {inner}"));

        let err = Result::<(), _>::Err(inner)
            .with_context(|| "failed to read")
            .unwrap_err();
        assert_eq!(format!("{err:#}"), format!("failed to read: {inner}"));
    }

    /// Check that we resolve debug links correctly.
    #[test]
    fn debug_link_resolution() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-stripped-with-link.bin");
        let resolver = DwarfResolver::open(&path).unwrap();
        assert!(resolver.linkee_parser.is_some());

        let linkee_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-dwarf-only.dbg");
        assert_eq!(
            resolver.linkee_parser.as_ref().unwrap().path(),
            Some(linkee_path.as_path())
        );
    }

    /// Check that we can find the source code location of an address.
    #[test]
    fn source_location_finding() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin");
        let resolver = DwarfResolver::open(bin_name.as_ref()).unwrap();

        let info = resolver
            .find_sym(0x2000100, &FindSymOpts::CodeInfo)
            .unwrap()
            .unwrap()
            .code_info
            .unwrap();
        assert_ne!(info.dir, Some(Cow::Owned(PathBuf::new())));
        assert_eq!(info.file, OsStr::new("test-stable-addrs.c"));
        assert_eq!(info.line, Some(10));
        assert!(info.column.is_some());
    }

    /// Check that we can look up a symbol in DWARF debug information.
    #[test]
    fn lookup_symbol() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            sym_type: SymType::Function,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref()).unwrap();

        let symbols = resolver.find_addr("factorial", &opts).unwrap();
        assert_eq!(symbols.len(), 1);

        // `factorial` resides at address 0x2000100.
        let symbol = symbols.first().unwrap();
        assert_eq!(symbol.addr, 0x2000100);
    }

    /// Check that we fail to look up variables.
    #[test]
    fn unsupported_ops() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            sym_type: SymType::Variable,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref()).unwrap();

        let err = resolver.find_addr("factorial", &opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);

        let err = resolver
            .for_each(&opts, &mut |_| ControlFlow::Continue(()))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}

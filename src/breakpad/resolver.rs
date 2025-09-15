use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem::swap;
use std::ops::ControlFlow;
use std::path::Path;
use std::path::PathBuf;

use crate::inspect::FindAddrOpts;
use crate::inspect::ForEachFn;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::log;
#[cfg(not(windows))]
use crate::mmap::Advice;
use crate::mmap::Mmap;
use crate::symbolize::CodeInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::InlinedFn;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;
use crate::SymType;

use super::types::Function;
use super::types::SymbolFile;


impl<'func> From<&'func Function> for SymInfo<'func> {
    #[inline]
    fn from(func: &'func Function) -> Self {
        Self {
            name: Cow::Borrowed(&func.name),
            addr: func.addr,
            size: Some(func.size as _),
            sym_type: SymType::Function,
            file_offset: None,
            module: None,
            _non_exhaustive: (),
        }
    }
}


/// A symbol resolver for a single Breakpad file.
pub struct BreakpadResolver {
    /// The parsed symbol file.
    symbol_file: SymbolFile,
    /// The path of the Breakpad file in use.
    path: PathBuf,
}

impl BreakpadResolver {
    /// Create a `BreakpadResolver` that loads data from the provided file.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("failed to open breakpad file `{}`", path.display()))?;
        Self::from_file(path.to_path_buf(), &file)
    }

    pub(crate) fn from_file(path: PathBuf, file: &File) -> Result<Self> {
        let mmap = Mmap::map(file)
            .with_context(|| format!("failed to memory map breakpad file `{}`", path.display()))?;
        // We are going to read the file in its entirety, so tell the
        // kernel about that.
        // Note that `PopulateRead` results in better performance still,
        // but comes with the drawback of seemingly promoting the
        // process to get killed earlier on OOM situations, which is not
        // something we want to get into.
        #[cfg(not(windows))]
        if let Err(err) = mmap.advise(Advice::WillNeed) {
            log::warn!("failed to madvise() mmap of `{}`: {err}", path.display());
        }

        let slf = Self {
            symbol_file: SymbolFile::from_bytes(&mmap)
                .with_context(|| format!("failed to parse Breakpad file `{}`", path.display()))?,
            path,
        };
        Ok(slf)
    }

    fn find_source_location(&self, file: u32) -> Result<(Option<&Path>, &OsStr)> {
        let path =
            self.symbol_file.files.get(&file).ok_or_invalid_input(|| {
                format!("failed to retrieve source file {file}: not found")
            })?;
        let mut comps = Path::new(path).components();
        let file = comps
            .next_back()
            .ok_or_invalid_input(|| format!("source file {file} does not contain a valid path"))?
            .as_os_str();
        let dir = comps.as_path();

        let dir = if dir.as_os_str().is_empty() {
            None
        } else {
            Some(dir)
        };
        Ok((dir, file))
    }

    fn find_inlinee_name(&self, origin_id: u32) -> Result<&str> {
        let name = self
            .symbol_file
            .inline_origins
            .get(&origin_id)
            .ok_or_invalid_input(|| {
                format!("failed to retrieve inlinee origin with {origin_id}: not found")
            })?;

        Ok(name)
    }

    fn fill_code_info<'slf>(
        &'slf self,
        sym: &mut ResolvedSym<'slf>,
        addr: Addr,
        opts: &FindSymOpts,
        func: &Function,
    ) -> Result<()> {
        if !opts.code_info() {
            return Ok(())
        }

        let source_line = if let Some(source_line) = func.find_line(addr) {
            source_line
        } else {
            return Ok(())
        };

        let (dir, file) = self.find_source_location(source_line.file)?;
        let mut direct_code_info = CodeInfo {
            dir: dir.map(Cow::Borrowed),
            file: Cow::Borrowed(file),
            line: Some(source_line.line),
            column: None,
            _non_exhaustive: (),
        };

        let inlined = if opts.inlined_fns() {
            let inline_stack = func.find_inlinees(addr);
            let mut inlined = Vec::<InlinedFn>::with_capacity(inline_stack.len());
            for inlinee in inline_stack {
                let name = self.find_inlinee_name(inlinee.origin_id)?;
                let (dir, file) = self.find_source_location(inlinee.call_file)?;
                let mut code_info = Some(CodeInfo {
                    dir: dir.map(Cow::Borrowed),
                    file: Cow::Borrowed(file),
                    line: Some(inlinee.call_line),
                    column: None,
                    _non_exhaustive: (),
                });

                if let Some(ref mut last_code_info) = inlined.last_mut().map(|f| &mut f.code_info) {
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
        };

        sym.code_info = Some(Box::new(direct_code_info));
        sym.inlined = inlined.into_boxed_slice();

        Ok(())
    }
}

impl Symbolize for BreakpadResolver {
    #[cfg_attr(feature = "tracing", crate::log::instrument(fields(addr = format_args!("{addr:#x}"))))]
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        let func = if let Some(func) = self.symbol_file.find_function(addr) {
            func
        } else {
            let reason = if self.symbol_file.functions.is_empty() {
                Reason::MissingSyms
            } else {
                Reason::UnknownAddr
            };
            return Ok(Err(reason))
        };

        let mut sym = ResolvedSym {
            name: &func.name,
            module: self.symbol_file.module.as_deref(),
            addr: func.addr,
            size: Some(func.size.try_into().unwrap_or(usize::MAX)),
            lang: SrcLang::Unknown,
            code_info: None,
            inlined: Box::new([]),
            _non_exhaustive: (),
        };
        let () = self.fill_code_info(&mut sym, addr, opts, func)?;

        Ok(Ok(sym))
    }
}

impl Inspect for BreakpadResolver {
    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported(
                "breakpad logic does not currently support variable lookup",
            ))
        }

        let syms = self
            .symbol_file
            .find_addr(name)
            .map(SymInfo::from)
            .collect::<Vec<_>>();

        Ok(syms)
    }

    /// Perform an operation on each symbol.
    fn for_each(&self, opts: &FindAddrOpts, f: &mut ForEachFn<'_>) -> Result<()> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported(
                "breakpad logic does not currently support variable iteration",
            ))
        }

        for func in &self.symbol_file.functions {
            let sym = SymInfo::from(func);
            if let ControlFlow::Break(()) = f(&sym) {
                return Ok(())
            }
        }
        Ok(())
    }
}

impl Debug for BreakpadResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Breakpad {}", self.path.display())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let sym_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.sym");

        let resolver = BreakpadResolver::open(sym_path).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("Breakpad"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addrs.sym"), "{dbg}");
    }

    /// Check that [`BreakpadResolver::find_addr`] and
    /// [`BreakpadResolver::for_each`] behave as expected.
    #[test]
    fn unsupported_ops() {
        let sym_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.sym");

        let resolver = BreakpadResolver::open(sym_path).unwrap();
        let opts = FindAddrOpts {
            sym_type: SymType::Variable,
            ..Default::default()
        };
        let err = resolver.find_addr("a_variable", &opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);

        let err = resolver
            .for_each(&opts, &mut |_| ControlFlow::Continue(()))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}

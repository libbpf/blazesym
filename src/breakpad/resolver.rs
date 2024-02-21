use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem::swap;
use std::path::Path;
use std::path::PathBuf;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::symbolize::AddrCodeInfo;
use crate::symbolize::CodeInfo;
use crate::symbolize::IntSym;
use crate::symbolize::Reason;
use crate::symbolize::SrcLang;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;
use crate::SymResolver;
use crate::SymType;

use super::types::Function;
use super::types::SymbolFile;


impl<'func> From<&'func Function> for SymInfo<'func> {
    #[inline]
    fn from(func: &'func Function) -> Self {
        Self {
            name: Cow::Borrowed(&func.name),
            addr: func.addr,
            size: func.size as _,
            sym_type: SymType::Function,
            file_offset: None,
            obj_file_name: None,
        }
    }
}


/// A symbol resolver for a single Breakpad file.
pub(crate) struct BreakpadResolver {
    /// The parsed symbol file.
    symbol_file: SymbolFile,
    /// The path of the Breakpad file in use.
    path: PathBuf,
}

impl BreakpadResolver {
    pub(crate) fn from_file(path: PathBuf, file: &File) -> Result<Self> {
        let slf = Self {
            symbol_file: SymbolFile::from_file(file)
                .with_context(|| format!("failed to parse Breakpad file `{path:?}`"))?,
            path,
        };
        Ok(slf)
    }

    fn find_source_location(&self, file: u32) -> Result<(Option<&Path>, &OsStr)> {
        let path = self.symbol_file.files.get(&file).ok_or_invalid_input(|| {
            format!("failed to retrieve source file {}: not found", file)
        })?;
        let mut comps = Path::new(path).components();
        let file = comps
            .next_back()
            .ok_or_invalid_input(|| format!("source file {} does not contain a valid path", file))?
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
                format!(
                    "failed to retrieve inlinee origin with {}: not found",
                    origin_id
                )
            })?;

        Ok(name)
    }

    /// Perform an operation on each symbol.
    pub(crate) fn for_each_sym<F, R>(&self, opts: &FindAddrOpts, mut r: R, mut f: F) -> Result<R>
    where
        F: FnMut(R, &SymInfo<'_>) -> R,
    {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported(
                "breakpad logic does not currently support variable iteration",
            ))
        }

        for func in &self.symbol_file.functions {
            let sym = SymInfo::from(func);
            r = f(r, &sym);
        }
        Ok(r)
    }
}

impl SymResolver for BreakpadResolver {
    #[cfg_attr(feature = "tracing", crate::log::instrument(fields(addr = format_args!("{addr:#x}"))))]
    fn find_sym(&self, addr: Addr) -> Result<Result<IntSym<'_>, Reason>> {
        if let Some(func) = self.symbol_file.find_function(addr) {
            let sym = IntSym {
                name: &func.name,
                addr: func.addr,
                size: Some(func.size.try_into().unwrap_or(usize::MAX)),
                lang: SrcLang::Unknown,
            };
            Ok(Ok(sym))
        } else {
            let reason = if self.symbol_file.functions.is_empty() {
                Reason::MissingSyms
            } else {
                Reason::UnknownAddr
            };
            Ok(Err(reason))
        }
    }

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

    fn find_code_info(&self, addr: Addr, inlined_fns: bool) -> Result<Option<AddrCodeInfo<'_>>> {
        // TODO: We really shouldn't be doing another `find_function`
        //       binary search here, conceptually. Consider merging
        //       `find_code_info` into `find_sym` at the `SymResolver`
        //       level.
        if let Some(func) = self.symbol_file.find_function(addr) {
            if let Some(source_line) = func.find_line(addr) {
                let (dir, file) = self.find_source_location(source_line.file)?;
                let mut direct_code_info = CodeInfo {
                    dir: dir.map(Cow::Borrowed),
                    file: Cow::Borrowed(file),
                    line: Some(source_line.line),
                    column: None,
                    _non_exhaustive: (),
                };

                let inlined = if inlined_fns {
                    let inline_stack = func.find_inlinees(addr);
                    let mut inlined = Vec::with_capacity(inline_stack.len());
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

                        if let Some((_last_name, ref mut last_code_info)) = inlined.last_mut() {
                            let () = swap(&mut code_info, last_code_info);
                        } else if let Some(code_info) = &mut code_info {
                            let () = swap(code_info, &mut direct_code_info);
                        }

                        let () = inlined.push((name, code_info));
                    }
                    inlined
                } else {
                    Vec::new()
                };

                let code_info = AddrCodeInfo {
                    direct: (None, direct_code_info),
                    inlined,
                };
                Ok(Some(code_info))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
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

    use std::path::Path;

    use test_log::test;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let sym_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.sym");
        let sym_file = File::open(&sym_path).unwrap();

        let resolver = BreakpadResolver::from_file(sym_path, &sym_file).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("Breakpad"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addresses.sym"), "{dbg}");
    }

    /// Check that [`BreakpadResolver::find_addr`] and
    /// [`BreakpadResolver::for_each_sym`] behave as expected.
    #[test]
    fn unsupported_ops() {
        let sym_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.sym");
        let sym_file = File::open(&sym_path).unwrap();

        let resolver = BreakpadResolver::from_file(sym_path, &sym_file).unwrap();
        let opts = FindAddrOpts {
            sym_type: SymType::Variable,
            ..Default::default()
        };
        let err = resolver.find_addr("a_variable", &opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);

        let err = resolver.for_each_sym(&opts, (), |(), _| ()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}

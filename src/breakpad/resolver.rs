use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
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

use super::types::SymbolFile;


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

    fn find_addr<'slf>(
        &'slf self,
        _name: &str,
        _opts: &FindAddrOpts,
    ) -> Result<Vec<SymInfo<'slf>>> {
        Err(Error::with_unsupported(
            "Breakpad resolver does not currently support lookup by name",
        ))
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
                let code_info = AddrCodeInfo {
                    direct: (None, direct_code_info),
                    inlined: Vec::new(),
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

    /// Check that [`BreakpadResolver::find_addr`] behaves as expected.
    #[test]
    fn unsupported_find_addr() {
        let sym_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.sym");
        let sym_file = File::open(&sym_path).unwrap();

        let resolver = BreakpadResolver::from_file(sym_path, &sym_file).unwrap();
        let err = resolver
            .find_addr("factorial", &FindAddrOpts::default())
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}

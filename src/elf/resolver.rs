use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::file_cache::FileCache;
use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::once::OnceCell;
use crate::symbolize::AddrCodeInfo;
use crate::symbolize::IntSym;
use crate::symbolize::Reason;
use crate::symbolize::SrcLang;
use crate::Addr;
use crate::Error;
use crate::Result;
use crate::SymResolver;
use crate::SymType;

use super::ElfBackend;
use super::ElfParser;


/// Resolver data associated with a specific source.
#[derive(Clone, Debug)]
pub(crate) struct ElfResolverData {
    /// A bare-bones ELF resolver.
    pub elf: OnceCell<Rc<ElfResolver>>,
    /// An ELF resolver with debug information enabled.
    pub dwarf: OnceCell<Rc<ElfResolver>>,
}

impl FileCache<ElfResolverData> {
    pub(crate) fn elf_resolver<'slf>(
        &'slf self,
        path: &Path,
        debug_syms: bool,
        code_info: bool,
    ) -> Result<&'slf Rc<ElfResolver>> {
        let (file, cell) = self.entry(path)?;
        let resolver = if let Some(data) = cell.get() {
            if debug_syms {
                data.dwarf.get_or_try_init(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `dwarf` part of it, the
                    //         `elf` part *must* be present.
                    let parser = data.elf.get().unwrap().parser().clone();
                    let resolver = ElfResolver::from_parser(path, parser, debug_syms, code_info)?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?
            } else {
                data.elf.get_or_try_init(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `elf` part of it, the
                    //         `dwarf` part *must* be present.
                    let parser = data.dwarf.get().unwrap().parser().clone();
                    let resolver = ElfResolver::from_parser(path, parser, debug_syms, code_info)?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?
            }
            .clone()
        } else {
            let parser = Rc::new(ElfParser::open_file(file)?);
            let resolver = ElfResolver::from_parser(path, parser, debug_syms, code_info)?;
            Rc::new(resolver)
        };

        let data = cell.get_or_init(|| {
            if debug_syms {
                ElfResolverData {
                    dwarf: OnceCell::from(resolver),
                    elf: OnceCell::new(),
                }
            } else {
                ElfResolverData {
                    dwarf: OnceCell::new(),
                    elf: OnceCell::from(resolver),
                }
            }
        });

        let resolver = if debug_syms {
            data.dwarf.get()
        } else {
            data.elf.get()
        };
        // SANITY: We made sure to create the desired resolver above.
        Ok(resolver.unwrap())
    }
}


/// The symbol resolver for a single ELF file.
///
/// An ELF file may be loaded into an address space with a relocation.
/// The callers should provide the path of an ELF file and where it's
/// executable segment(s) is loaded.
///
/// For some ELF files, they are located at a specific address
/// determined during compile-time.  For these cases, just pass `0` as
/// it's loaded address.
pub struct ElfResolver {
    backend: ElfBackend,
    file_name: PathBuf,
}

impl ElfResolver {
    pub(crate) fn with_backend(file_name: &Path, backend: ElfBackend) -> Result<ElfResolver> {
        Ok(ElfResolver {
            backend,
            file_name: file_name.to_path_buf(),
        })
    }

    pub(crate) fn from_parser(
        path: &Path,
        parser: Rc<ElfParser>,
        _debug_syms: bool,
        code_info: bool,
    ) -> Result<Self> {
        #[cfg(feature = "dwarf")]
        let backend = if _debug_syms {
            let dwarf = DwarfResolver::from_parser(parser, code_info)?;
            let backend = ElfBackend::Dwarf(Rc::new(dwarf));
            backend
        } else {
            ElfBackend::Elf(parser)
        };

        #[cfg(not(feature = "dwarf"))]
        let backend = ElfBackend::Elf(parser);

        let resolver = ElfResolver::with_backend(path, backend)?;
        Ok(resolver)
    }

    pub(crate) fn parser(&self) -> &Rc<ElfParser> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.parser(),
            ElfBackend::Elf(parser) => parser,
        }
    }

    /// Retrieve the path to the ELF file represented by this resolver.
    pub(crate) fn file_name(&self) -> &Path {
        &self.file_name
    }
}

impl SymResolver for ElfResolver {
    #[cfg_attr(feature = "tracing", crate::log::instrument(fields(addr = format_args!("{addr:#x}"))))]
    fn find_sym(&self, addr: Addr) -> Result<Result<IntSym<'_>, Reason>> {
        #[cfg(feature = "dwarf")]
        if let ElfBackend::Dwarf(dwarf) = &self.backend {
            if let Some(sym) = dwarf.find_sym(addr)? {
                return Ok(Ok(sym))
            }
        }

        let parser = self.parser();
        let result = parser
            .find_sym(addr, SymType::Undefined)?
            .map(|(name, addr, size)| {
                // ELF does not carry any source code language information.
                let lang = SrcLang::Unknown;
                // We found the address in ELF.
                // TODO: Long term we probably want a different heuristic here, as
                //       there can be valid differences between the two formats
                //       (e.g., DWARF could contain more symbols).
                let sym = IntSym {
                    name,
                    addr,
                    size: Some(size),
                    lang,
                };
                sym
            });

        Ok(result)
    }

    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        fn find_addr_impl<'slf>(
            slf: &'slf ElfResolver,
            name: &str,
            opts: &FindAddrOpts,
        ) -> Result<Vec<SymInfo<'slf>>> {
            #[cfg(feature = "dwarf")]
            if let ElfBackend::Dwarf(dwarf) = &slf.backend {
                let syms = dwarf.find_addr(name, opts)?;
                if !syms.is_empty() {
                    return Ok(syms)
                }
            }

            let parser = slf.parser();
            let syms = parser.find_addr(name, opts)?;
            Ok(syms)
        }

        let mut syms = find_addr_impl(self, name, opts)?;
        let () = syms
            .iter_mut()
            .for_each(|sym| sym.obj_file_name = Some(Cow::Borrowed(&self.file_name)));
        Ok(syms)
    }

    #[cfg(feature = "dwarf")]
    fn find_code_info(&self, addr: Addr, inlined_fns: bool) -> Result<Option<AddrCodeInfo<'_>>> {
        if let ElfBackend::Dwarf(dwarf) = &self.backend {
            dwarf.find_code_info(addr, inlined_fns)
        } else {
            Ok(None)
        }
    }

    #[cfg(not(feature = "dwarf"))]
    fn find_code_info(&self, addr: Addr, inlined_fns: bool) -> Result<Option<AddrCodeInfo<'_>>> {
        Ok(None)
    }
}

impl Debug for ElfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(_) => write!(f, "DWARF {}", self.file_name.display()),
            ElfBackend::Elf(_) => write!(f, "ELF {}", self.file_name.display()),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::dwarf::DwarfResolver;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.bin");

        let parser = Rc::new(ElfParser::open(&path).unwrap());
        let backend = ElfBackend::Elf(parser.clone());
        let resolver = ElfResolver::with_backend(&path, backend).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("ELF"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addresses.bin"), "{dbg}");

        let dwarf = DwarfResolver::from_parser(parser, true).unwrap();
        let backend = ElfBackend::Dwarf(Rc::new(dwarf));
        let resolver = ElfResolver::with_backend(&path, backend).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("DWARF"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addresses.bin"), "{dbg}");
    }

    /// Check that we fail finding an offset for an address not
    /// representing a symbol in an ELF file.
    #[test]
    fn addr_without_offset() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");
        let parser = ElfParser::open(&path).unwrap();

        assert_eq!(parser.find_file_offset(0x0).unwrap(), None);
        assert_eq!(parser.find_file_offset(0xffffffffffffffff).unwrap(), None);
    }
}

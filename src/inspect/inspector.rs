use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::elf::ElfBackend;
use crate::elf::ElfParser;
use crate::elf::ElfResolver;
use crate::file_cache::FileCache;
use crate::Result;
use crate::SymResolver;

use super::source::Elf;
use super::source::Source;
use super::FindAddrOpts;
use super::SymInfo;
use super::SymType;


/// An inspector of various "sources".
///
/// Object of this type can be used to perform inspections of supported sources.
/// E.g., using an ELF file as a source, information about a symbol can be
/// inquired based on its name.
///
/// An instance of this type is the unit at which inspection inputs are cached.
/// That is to say, source files (such as ELF) and the parsed data structures
/// may be kept around in memory for the lifetime of this object to speed up
/// future inspection requests.
/// If you are working with large input sources and/or do not intend to perform
/// multiple inspection requests for the same symbolization source, you may want
/// to consider creating a new `Inspector` instance regularly.
#[derive(Debug)]
pub struct Inspector {
    elf_cache: RefCell<FileCache<Rc<ElfResolver>>>,
}

impl Inspector {
    /// Create a new `Inspector`.
    pub fn new() -> Self {
        Self {
            elf_cache: RefCell::new(FileCache::new()),
        }
    }

    // TODO: Overlap with similar functionality in the `Symbolizer`. Need to
    //       deduplicate at some point.
    fn elf_resolver_from_parser(
        &self,
        path: &Path,
        parser: Rc<ElfParser>,
        debug_info: bool,
    ) -> Result<Rc<ElfResolver>> {
        #[cfg(feature = "dwarf")]
        let backend = if debug_info {
            let debug_line_info = true;
            let debug_info_symbols = true;
            let dwarf = DwarfResolver::from_parser(parser, debug_line_info, debug_info_symbols)?;
            let backend = ElfBackend::Dwarf(Rc::new(dwarf));
            backend
        } else {
            ElfBackend::Elf(parser)
        };

        #[cfg(not(feature = "dwarf"))]
        let backend = ElfBackend::Elf(parser);

        let resolver = Rc::new(ElfResolver::with_backend(path, backend)?);
        Ok(resolver)
    }

    fn elf_resolver(&self, path: &Path, debug_info: bool) -> Result<Rc<ElfResolver>> {
        let mut cache = self.elf_cache.borrow_mut();
        let (file, entry) = cache.entry(path)?;
        let resolver = if let Some(resolver) = entry {
            if resolver.uses_dwarf() == debug_info {
                resolver.clone()
            } else {
                self.elf_resolver_from_parser(path, resolver.parser().clone(), debug_info)?
            }
        } else {
            let parser = Rc::new(ElfParser::open_file(file)?);
            self.elf_resolver_from_parser(path, parser, debug_info)?
        };

        *entry = Some(resolver.clone());
        Ok(resolver)
    }

    /// Look up information (address etc.) about a list of symbols,
    /// given their names.
    pub fn lookup(&self, names: &[&str], src: &Source) -> Result<Vec<Vec<SymInfo>>> {
        let opts = FindAddrOpts {
            offset_in_file: true,
            obj_file_name: true,
            sym_type: SymType::Unknown,
        };

        match src {
            Source::Elf(Elf {
                path,
                debug_info,
                _non_exhaustive: (),
            }) => {
                let resolver = self.elf_resolver(path, *debug_info)?;
                let syms = names
                    .iter()
                    .map(|name| {
                        let mut syms = resolver.find_addr(name, &opts).unwrap_or_default();
                        let () = syms.iter_mut().for_each(|sym| {
                            if opts.offset_in_file {
                                if let Some(off) = resolver.addr_file_off(sym.addr) {
                                    sym.file_offset = off;
                                }
                            }
                            if opts.obj_file_name {
                                sym.obj_file_name = Some(path.to_path_buf())
                            }
                        });

                        syms
                    })
                    .collect();

                Ok(syms)
            }
        }
    }
}

impl Default for Inspector {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let inspector = Inspector::default();
        assert_ne!(format!("{inspector:?}"), "");
    }

    /// Check that we error our as expected when encountering a source
    /// that is not present.
    #[test]
    fn non_present_file() {
        fn test(src: &Source) {
            let inspector = Inspector::new();
            let err = inspector.lookup(&["factorial"], src).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::NotFound);
        }

        let file = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("does-not-exist");
        let src = Source::Elf(Elf::new(&file));
        let () = test(&src);

        let mut elf = Elf::new(file);
        elf.debug_info = !elf.debug_info;
        let src = Source::Elf(elf);
        let () = test(&src);
    }

    /// Check that ELF resolver caching works as expected.
    #[test]
    fn elf_resolver_caching() {
        let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");
        let mut elf = Elf::new(&test_elf);
        assert!(elf.debug_info);

        let inspector = Inspector::new();
        let resolver = || {
            let mut cache = inspector.elf_cache.borrow_mut();
            cache.entry(&test_elf).unwrap().1.as_ref().unwrap().clone()
        };

        let _results = inspector.lookup(&["factorial"], &Source::Elf(elf.clone()));
        let resolver1 = resolver();

        let _results = inspector.lookup(&["factorial"], &Source::Elf(elf.clone()));
        let resolver2 = resolver();
        assert!(Rc::ptr_eq(&resolver1, &resolver2));

        // When changing whether we use debug information we should create a new
        // resolver.
        elf.debug_info = false;

        let _results = inspector.lookup(&["factorial"], &Source::Elf(elf.clone()));
        let resolver3 = resolver();
        assert!(!Rc::ptr_eq(&resolver1, &resolver3));
    }
}

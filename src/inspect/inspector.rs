use std::path::Path;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::elf::ElfBackend;
use crate::elf::ElfParser;
use crate::elf::ElfResolver;
use crate::file_cache::FileCache;
use crate::once::OnceCell;
use crate::Result;
use crate::SymResolver;

use super::source::Elf;
use super::source::Source;
use super::FindAddrOpts;
use super::SymInfo;
use super::SymType;


/// Resolver data associated with a specific source.
#[derive(Clone, Debug)]
struct ResolverData {
    /// A bare-bones ELF resolver.
    elf: OnceCell<Rc<ElfResolver>>,
    /// An ELF resolver with debug information enabled.
    dwarf: OnceCell<Rc<ElfResolver>>,
}


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
    elf_cache: FileCache<ResolverData>,
}

impl Inspector {
    /// Create a new `Inspector`.
    pub fn new() -> Self {
        Self {
            elf_cache: FileCache::new(),
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
            let dwarf = DwarfResolver::from_parser(parser, debug_line_info)?;
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
        let (file, cell) = self.elf_cache.entry(path)?;
        let resolver = if let Some(data) = cell.get() {
            if debug_info {
                data.dwarf.get_or_try_init(|| {
                    // SANITY: We *know* a `ResolverData` object is present and
                    //         given that we are initializing the `dwarf` part
                    //         of it, the `elf` part *must* be present.
                    let parser = data.elf.get().unwrap().parser().clone();
                    self.elf_resolver_from_parser(path, parser, true)
                })?
            } else {
                data.elf.get_or_try_init(|| {
                    // SANITY: We *know* a `ResolverData` object is present and
                    //         given that we are initializing the `elf` part of
                    //         it, the `dwarf` part *must* be present.
                    let parser = data.dwarf.get().unwrap().parser().clone();
                    self.elf_resolver_from_parser(path, parser, false)
                })?
            }
            .clone()
        } else {
            let parser = Rc::new(ElfParser::open_file(file)?);
            self.elf_resolver_from_parser(path, parser, debug_info)?
        };

        let _data = cell.get_or_init(|| {
            if debug_info {
                ResolverData {
                    dwarf: OnceCell::from(resolver.clone()),
                    elf: OnceCell::new(),
                }
            } else {
                ResolverData {
                    dwarf: OnceCell::new(),
                    elf: OnceCell::from(resolver.clone()),
                }
            }
        });

        Ok(resolver)
    }

    /// Look up information (address etc.) about a list of symbols,
    /// given their names.
    ///
    /// # Notes
    /// - no symbol name demangling is performed currently
    pub fn lookup<'slf>(
        &'slf self,
        names: &[&str],
        src: &Source,
    ) -> Result<Vec<Vec<SymInfo<'slf>>>> {
        let opts = FindAddrOpts {
            offset_in_file: true,
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
                        resolver.find_addr(name, &opts).map(|syms| {
                            // This dance including reallocation of the vector
                            // is very unfortunate, but it's unclear how else to
                            // make the borrow checker accept this code (modulo
                            // `transmute`).
                            syms.into_iter().map(|sym| sym.to_owned()).collect()
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok(syms)
            }
        }
    }

    /// Perform an operation on each symbol in the source.
    ///
    /// Symbols are reported in implementation defined order that should
    /// not be relied on.
    ///
    /// # Notes
    /// - no symbol name demangling is performed currently
    /// - currently only function symbols (as opposed to variables) are
    ///   reported
    /// - undefined symbols (such as ones referencing a different shared
    ///   object) are not reported
    /// - for the [`Elf`](Source::Elf) source, at present DWARF symbols are
    ///   ignored (irrespective of the [`debug_info`][Elf::debug_info]
    ///   configuration)
    pub fn for_each<F, R>(&self, src: &Source, r: R, f: F) -> Result<R>
    where
        F: FnMut(R, &SymInfo<'_>) -> R,
    {
        match src {
            Source::Elf(Elf {
                path,
                debug_info,
                _non_exhaustive: (),
            }) => {
                let opts = FindAddrOpts {
                    offset_in_file: true,
                    sym_type: SymType::Unknown,
                };
                let resolver = self.elf_resolver(path, *debug_info)?;
                let parser = resolver.parser();
                parser.for_each_sym(&opts, r, f)
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
        let data = || {
            inspector
                .elf_cache
                .entry(&test_elf)
                .unwrap()
                .1
                .get()
                .unwrap()
                .clone()
        };

        let _results = inspector.lookup(&["factorial"], &Source::Elf(elf.clone()));
        let data1 = data();

        let _results = inspector.lookup(&["factorial"], &Source::Elf(elf.clone()));
        let data2 = data();
        assert!(Rc::ptr_eq(
            data1.dwarf.get().unwrap(),
            data2.dwarf.get().unwrap()
        ));

        // When changing whether we use debug information we should create a new
        // resolver.
        elf.debug_info = false;

        let _results = inspector.lookup(&["factorial"], &Source::Elf(elf.clone()));
        let data3 = data();
        assert!(!Rc::ptr_eq(
            data1.dwarf.get().unwrap(),
            data3.elf.get().unwrap()
        ));
    }
}

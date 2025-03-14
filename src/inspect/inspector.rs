#[cfg(feature = "breakpad")]
use std::fs::File;
use std::ops::ControlFlow;
use std::ops::Deref as _;
#[cfg(feature = "breakpad")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "breakpad")]
use crate::breakpad::BreakpadResolver;
use crate::elf::ElfResolverData;
use crate::elf::DEFAULT_DEBUG_DIRS;
use crate::file_cache::FileCache;
use crate::inspect::ForEachFn;
use crate::Result;

#[cfg(feature = "breakpad")]
use super::source::Breakpad;
use super::source::Elf;
use super::source::Source;
use super::FindAddrOpts;
use super::Inspect;
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
    #[cfg(feature = "breakpad")]
    breakpad_cache: FileCache<Box<BreakpadResolver>>,
    elf_cache: FileCache<ElfResolverData>,
}

impl Inspector {
    /// Create a new `Inspector`.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "breakpad")]
            breakpad_cache: FileCache::builder().enable_auto_reload(true).build(),
            // TODO: Make auto reloading configurable by clients.
            elf_cache: FileCache::builder().enable_auto_reload(true).build(),
        }
    }

    #[cfg(feature = "breakpad")]
    fn create_breakpad_resolver(&self, path: &Path, file: &File) -> Result<Box<BreakpadResolver>> {
        let resolver = BreakpadResolver::from_file(path.to_path_buf(), file)?;
        Ok(Box::new(resolver))
    }

    #[cfg(feature = "breakpad")]
    fn breakpad_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf BreakpadResolver> {
        let (file, cell) = self.breakpad_cache.entry(path)?;
        let resolver = cell.get_or_try_init(|| self.create_breakpad_resolver(path, file))?;
        Ok(resolver)
    }

    /// Look up information (address etc.) about a list of symbols,
    /// given their names.
    ///
    /// On success, this returns a vector of vectors of symbol information.
    /// For each symbol name, a vector of addresses is returned, i.e. a given
    /// symbol name can correspond to more than one address.
    ///
    /// If you require some kind of advanced look up scheme, e.g., based on a
    /// regular expression matching or on demangled names when the source
    /// contains only mangled symbols, this will have to be built on top of the
    /// [`Inspector::for_each`] functionality.
    ///
    /// # Notes
    /// - no symbol name demangling is performed and data is reported as it
    ///   appears in the symbol source
    /// - for the [`Breakpad`](Source::Breakpad) source:
    ///   - no variable support is present
    ///   - file offsets won't be reported
    ///   - addresses are reported as they appear in the symbol source
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, names = ?names), err))]
    pub fn lookup<'slf>(
        &'slf self,
        src: &Source,
        names: &[&str],
    ) -> Result<Vec<Vec<SymInfo<'slf>>>> {
        let opts = FindAddrOpts {
            file_offset: true,
            sym_type: SymType::Undefined,
        };

        let resolver = match src {
            #[cfg(feature = "breakpad")]
            Source::Breakpad(Breakpad {
                path,
                _non_exhaustive: (),
            }) => {
                let resolver = self.breakpad_resolver(path)?;
                resolver as &dyn Inspect
            }
            Source::Elf(Elf {
                path,
                debug_syms,
                _non_exhaustive: (),
            }) => {
                let debug_dirs;
                let resolver = self.elf_cache.elf_resolver(
                    path.as_path(),
                    if *debug_syms {
                        debug_dirs = DEFAULT_DEBUG_DIRS
                            .iter()
                            .map(PathBuf::from)
                            .collect::<Vec<_>>();
                        Some(debug_dirs.as_slice())
                    } else {
                        None
                    },
                )?;
                resolver.deref() as &dyn Inspect
            }
        };

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

    /// Perform an operation on each symbol in the source.
    ///
    /// Symbols are reported in implementation defined order that should
    /// not be relied on.
    ///
    /// To stop symbol iteration early, return [`ControlFlow::Break`] from the
    /// callback function.
    ///
    /// # Notes
    /// - no symbol name demangling is performed and data is reported as it
    ///   appears in the symbol source
    /// - undefined symbols (such as ones referencing a different shared object)
    ///   are not reported
    /// - for the [`Elf`](Source::Elf) source:
    ///   - if `debug_syms` is set, *only* debug symbols are consulted and no
    ///     support for variables is present
    /// - for the [`Breakpad`](Source::Breakpad) source:
    ///   - no variable support is present
    ///   - file offsets won't be reported
    ///   - addresses are reported as they appear in the symbol source
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src), err))]
    pub fn for_each<F>(&self, src: &Source, mut f: F) -> Result<()>
    where
        F: FnMut(&SymInfo<'_>) -> ControlFlow<()>,
    {
        fn for_each_impl(slf: &Inspector, src: &Source, f: &mut ForEachFn<'_>) -> Result<()> {
            let (resolver, opts) = match src {
                #[cfg(feature = "breakpad")]
                Source::Breakpad(Breakpad {
                    path,
                    _non_exhaustive: (),
                }) => {
                    let opts = FindAddrOpts {
                        // Breakpad logic doesn't support file offsets.
                        file_offset: false,
                        sym_type: SymType::Undefined,
                    };
                    let resolver = slf.breakpad_resolver(path)?;
                    (resolver as &dyn Inspect, opts)
                }
                Source::Elf(Elf {
                    path,
                    debug_syms,
                    _non_exhaustive: (),
                }) => {
                    let opts = FindAddrOpts {
                        file_offset: true,
                        sym_type: SymType::Undefined,
                    };
                    let debug_dirs;
                    let resolver = slf.elf_cache.elf_resolver(
                        path.as_path(),
                        if *debug_syms {
                            debug_dirs = DEFAULT_DEBUG_DIRS
                                .iter()
                                .map(PathBuf::from)
                                .collect::<Vec<_>>();
                            Some(debug_dirs.as_slice())
                        } else {
                            None
                        },
                    )?;
                    (resolver.deref() as &dyn Inspect, opts)
                }
            };

            resolver.for_each(&opts, f)
        }

        for_each_impl(self, src, &mut f)
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

    #[cfg(not(feature = "breakpad"))]
    use std::path::Path;
    use std::rc::Rc;

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
            let err = inspector.lookup(src, &["factorial"]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::NotFound);
        }

        let file = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("does-not-exist");
        let src = Source::Elf(Elf::new(&file));
        let () = test(&src);

        let mut elf = Elf::new(file);
        elf.debug_syms = !elf.debug_syms;
        let src = Source::Elf(elf);
        let () = test(&src);
    }

    /// Check that ELF resolver caching works as expected.
    #[test]
    fn elf_resolver_caching() {
        let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin");
        let mut elf = Elf::new(&test_elf);
        assert!(elf.debug_syms);

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

        let _results = inspector.lookup(&Source::Elf(elf.clone()), &["factorial"]);
        let data1 = data();

        let _results = inspector.lookup(&Source::Elf(elf.clone()), &["factorial"]);
        let data2 = data();
        assert!(Rc::ptr_eq(
            data1.dwarf.get().unwrap(),
            data2.dwarf.get().unwrap()
        ));

        // When changing whether we use debug symbols we should create a
        // new resolver.
        elf.debug_syms = false;

        let _results = inspector.lookup(&Source::Elf(elf.clone()), &["factorial"]);
        let data3 = data();
        assert!(!Rc::ptr_eq(
            data1.dwarf.get().unwrap(),
            data3.elf.get().unwrap()
        ));
    }
}

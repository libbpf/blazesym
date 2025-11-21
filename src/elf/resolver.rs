use std::cell::OnceCell;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::elf::DEFAULT_DEBUG_DIRS;
use crate::file_cache::FileCache;
use crate::inspect::FindAddrOpts;
use crate::inspect::ForEachFn;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::pathlike::PathLike;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::Symbolize;
use crate::symbolize::TranslateFileOffset;
use crate::util::OnceCellExt as _;
use crate::Addr;
use crate::Error;
use crate::Result;

use super::ElfParser;


#[derive(Clone, Debug)]
enum ElfBackend {
    #[cfg(feature = "dwarf")]
    Dwarf(Rc<DwarfResolver>), // ELF w/ DWARF
    Elf(Rc<ElfParser>), // ELF w/o DWARF
}


/// Resolver data associated with a specific source.
#[derive(Clone, Debug)]
pub(crate) struct ElfResolverData {
    /// A bare-bones ELF resolver.
    pub elf: OnceCell<Rc<ElfResolver>>,
    /// An ELF resolver with debug information enabled.
    pub dwarf: OnceCell<Rc<ElfResolver>>,
}

impl From<Rc<ElfResolver>> for ElfResolverData {
    fn from(other: Rc<ElfResolver>) -> Self {
        match other.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(..) => Self {
                dwarf: OnceCell::from(other),
                elf: OnceCell::new(),
            },
            ElfBackend::Elf(..) => Self {
                dwarf: OnceCell::new(),
                elf: OnceCell::from(other),
            },
        }
    }
}

impl FileCache<ElfResolverData> {
    /// Create an `ElfResolver`.
    ///
    /// If `debug_dirs` is `Some` then debug information will be used
    /// and the provided list of debug directories consulted when
    /// following debug links.
    /// If `debug_dirs` is `None` only ELF symbols will be consulted.
    pub(crate) fn elf_resolver<'slf>(
        &'slf self,
        path: &dyn PathLike,
        debug_dirs: Option<&[PathBuf]>,
    ) -> Result<&'slf Rc<ElfResolver>> {
        let (file, cell) = self.entry(path.actual_path())?;
        let resolver = if let Some(data) = cell.get() {
            let resolver = if debug_dirs.is_some() {
                data.dwarf.get_or_try_init_(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `dwarf` part of it, the
                    //         `elf` part *must* be present.
                    let parser = Rc::clone(data.elf.get().unwrap().parser());
                    let resolver = ElfResolver::from_parser(parser, debug_dirs, Some(self))?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?
            } else {
                data.elf.get_or_try_init_(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `elf` part of it, the
                    //         `dwarf` part *must* be present.
                    let parser = Rc::clone(data.dwarf.get().unwrap().parser());
                    let resolver = ElfResolver::from_parser(parser, debug_dirs, Some(self))?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?
            };
            Rc::clone(resolver)
        } else {
            let module = path.represented_path().as_os_str().to_os_string();
            let parser = Rc::new(ElfParser::from_file(file, module)?);
            let resolver = ElfResolver::from_parser(parser, debug_dirs, Some(self))?;
            Rc::new(resolver)
        };

        let data = cell.get_or_init(|| {
            if debug_dirs.is_some() {
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

        let resolver = if debug_dirs.is_some() {
            data.dwarf.get()
        } else {
            data.elf.get()
        };
        // SANITY: We made sure to create the desired resolver above.
        Ok(resolver.unwrap())
    }

    /// Register an existing `ElfResolver` for a given path.
    pub(crate) fn register(&self, path: &Path, elf_resolver: Rc<ElfResolver>) -> Result<()> {
        // TODO: Need to use passed-in `ElfResolver`'s file instead of
        //       opening a new one here. Doing so will need adjustments
        //       to `FileCache` API.
        let (_file, cell) = self.entry(path.actual_path())?;
        // We only allow the call to succeed if no `ElfResolverData` is
        // set at all, to prevent any potential confusion with different
        // `ElfParser`s being shared between the DWARF and ELF
        // attributes of the type.
        let () = cell.set(ElfResolverData::from(elf_resolver)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "ELF resolver object alread set for path `{}`",
                    path.display()
                ),
            )
        })?;
        Ok(())
    }
}

/// The symbol resolver for a single ELF file.
pub struct ElfResolver {
    backend: ElfBackend,
}

impl ElfResolver {
    /// Create an `ElfResolver` that loads data from the provided file.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let parser = Rc::new(ElfParser::open(path)?);
        let debug_dirs = DEFAULT_DEBUG_DIRS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let elf_cache = None;
        Self::from_parser(parser, Some(&debug_dirs), elf_cache)
    }

    /// Create a new [`ElfResolver`] using `parser`.
    ///
    /// If `debug_dirs` is `Some`, interpret DWARF debug information. If it is
    /// `None`, just look at ELF symbols.
    pub(crate) fn from_parser(
        parser: Rc<ElfParser>,
        debug_dirs: Option<&[PathBuf]>,
        _elf_cache: Option<&FileCache<ElfResolverData>>,
    ) -> Result<Self> {
        #[cfg(feature = "dwarf")]
        let backend = if let Some(debug_dirs) = debug_dirs {
            let dwarf = DwarfResolver::from_parser(parser, debug_dirs)?;
            let backend = ElfBackend::Dwarf(Rc::new(dwarf));
            backend
        } else {
            ElfBackend::Elf(parser)
        };

        #[cfg(not(feature = "dwarf"))]
        let backend = ElfBackend::Elf(parser);

        let resolver = ElfResolver { backend };
        Ok(resolver)
    }

    pub(crate) fn parser(&self) -> &Rc<ElfParser> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.parser(),
            ElfBackend::Elf(parser) => parser,
        }
    }

    pub(crate) fn cache(&self) -> Result<()> {
        // TODO: Does not yet work for debug symbols.
        let () = self.parser().cache()?;
        Ok(())
    }
}

impl Symbolize for ElfResolver {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.find_sym(addr, opts),
            ElfBackend::Elf(parser) => parser.find_sym(addr, opts),
        }
    }
}

impl TranslateFileOffset for ElfResolver {
    fn file_offset_to_virt_offset(&self, file_offset: u64) -> Result<Option<Addr>> {
        let parser = self.parser();
        parser.file_offset_to_virt_offset(file_offset)
    }
}

impl Inspect for ElfResolver {
    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.find_addr(name, opts),
            ElfBackend::Elf(parser) => parser.find_addr(name, opts),
        }
    }

    fn for_each(&self, opts: &FindAddrOpts, f: &mut ForEachFn<'_>) -> Result<()> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.for_each(opts, f),
            ElfBackend::Elf(parser) => parser.for_each(opts, f),
        }
    }
}

impl Debug for ElfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => Debug::fmt(dwarf, f),
            ElfBackend::Elf(elf) => Debug::fmt(elf, f),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin");
        let elf_cache = None;

        let parser = Rc::new(ElfParser::open(path.as_path()).unwrap());
        let debug_dirs = None;
        let resolver = ElfResolver::from_parser(Rc::clone(&parser), debug_dirs, elf_cache).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("ElfParser("), "{dbg}");
        assert!(dbg.ends_with("test-stable-addrs.bin\")"), "{dbg}");

        let debug_dirs = Some([].as_slice());
        let resolver = ElfResolver::from_parser(parser, debug_dirs, elf_cache).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("DwarfResolver("), "{dbg}");
        assert!(dbg.ends_with("test-stable-addrs.bin\")"), "{dbg}");
    }

    /// Exercise the [`ElfResolverData`] conversion from an
    /// [`ElfResolver`].
    #[test]
    fn elf_resolver_data_conversion() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin");
        let elf_cache = None;

        let parser = Rc::new(ElfParser::open(path.as_path()).unwrap());
        let debug_dirs = None;
        let resolver = ElfResolver::from_parser(Rc::clone(&parser), debug_dirs, elf_cache).unwrap();
        let data = ElfResolverData::from(Rc::new(resolver));
        let _resolver = data.elf.get_or_init(|| panic!());

        let debug_dirs = Some([].as_slice());
        let resolver = ElfResolver::from_parser(parser, debug_dirs, elf_cache).unwrap();
        let data = ElfResolverData::from(Rc::new(resolver));
        let _resolver = data.dwarf.get_or_init(|| panic!());
    }

    /// Check that we fail finding an offset for an address not
    /// representing a symbol in an ELF file.
    #[test]
    fn addr_without_offset() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin");
        let parser = ElfParser::open(path.as_path()).unwrap();

        let size = 0;
        assert_eq!(parser.find_file_offset(0x0, size).unwrap(), None);
        assert_eq!(
            parser.find_file_offset(0xffffffffffffffff, size).unwrap(),
            None
        );
    }
}

use std::cell::OnceCell;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::elf::ElfResolverData;
use crate::file_cache::FileCache;
use crate::pathlike::PathLike;
use crate::util::OnceCellExt as _;
use crate::ErrorExt as _;
use crate::Result;

use super::kaslr::find_kalsr_offset;
use super::ksym::KsymResolver;
use super::DepmodIndex;
use super::ModMap;
use super::MODULES;


/// A cache for kernel related data.
#[derive(Debug)]
pub(crate) struct KernelCache {
    /// Cache of ELF files.
    elf_cache: FileCache<ElfResolverData>,
    /// `/proc/kallsyms` cache.
    ksym_cache: FileCache<Rc<KsymResolver>>,
    /// The system's module map (`/proc/modules`).
    modmap: OnceCell<ModMap>,
    /// The system's depmod index.
    depmod: OnceCell<DepmodIndex>,
    /// The system's KASLR offset.
    kaslr_offset: OnceCell<u64>,
    #[cfg(feature = "dwarf")]
    debug_dirs: Rc<[PathBuf]>,
}

impl KernelCache {
    #[cfg(feature = "dwarf")]
    pub fn new(debug_dirs: Rc<[PathBuf]>) -> Self {
        Self {
            elf_cache: FileCache::default(),
            ksym_cache: FileCache::default(),
            modmap: OnceCell::default(),
            depmod: OnceCell::default(),
            kaslr_offset: OnceCell::default(),
            debug_dirs,
        }
    }

    #[cfg(not(feature = "dwarf"))]
    pub fn new() -> Self {
        Self {
            elf_cache: FileCache::default(),
            ksym_cache: FileCache::default(),
            modmap: OnceCell::default(),
            depmod: OnceCell::default(),
            kaslr_offset: OnceCell::default(),
        }
    }

    fn maybe_debug_dirs(&self, debug_syms: bool) -> Option<&[PathBuf]> {
        #[cfg(feature = "dwarf")]
        let debug_dirs = &self.debug_dirs;
        #[cfg(not(feature = "dwarf"))]
        let debug_dirs = &[];
        debug_syms.then_some(debug_dirs)
    }

    pub fn elf_resolver<'slf>(
        &'slf self,
        path: &dyn PathLike,
        debug_syms: bool,
    ) -> Result<&'slf Rc<ElfResolver>> {
        self.elf_cache
            .elf_resolver(path, self.maybe_debug_dirs(debug_syms))
    }

    fn create_ksym_resolver(&self, path: &Path, file: &File) -> Result<Rc<KsymResolver>> {
        let resolver = KsymResolver::load_from_reader(file, path)?;
        let resolver = Rc::new(resolver);
        Ok(resolver)
    }

    pub fn ksym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf Rc<KsymResolver>> {
        let (file, cell) = self.ksym_cache.entry(path)?;
        let resolver = cell.get_or_try_init_(|| self.create_ksym_resolver(path, file))?;
        Ok(resolver)
    }

    pub fn modmap(&self) -> Result<&ModMap> {
        self.modmap
            .get_or_try_init_(|| ModMap::new(Path::new(MODULES)))
    }

    #[cfg(linux)]
    pub fn depmod(&self) -> Result<&DepmodIndex> {
        self.depmod
            .get_or_try_init_(DepmodIndex::with_system_default)
            .context("failed to read system depmod information")
    }

    #[cfg(not(linux))]
    pub fn depmod(&self) -> Result<&DepmodIndex> {
        unimplemented!()
    }

    pub fn kaslr_offset(&self) -> Result<u64> {
        self.kaslr_offset
            .get_or_try_init_(|| {
                find_kalsr_offset()
                    .context("failed to query system KASLR offset")
                    .map(Option::unwrap_or_default)
            })
            .copied()
    }
}

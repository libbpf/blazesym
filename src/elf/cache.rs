use std::collections::hash_map;
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::util::fstat;
use crate::ErrorExt as _;
use crate::Result;

use super::ElfParser;


#[derive(Clone, Debug)]
pub(crate) enum ElfBackend {
    #[cfg(feature = "dwarf")]
    Dwarf(Rc<DwarfResolver>), // ELF w/ DWARF
    Elf(Rc<ElfParser>), // ELF w/o DWARF
}

impl ElfBackend {
    /// Retrieve the underlying [`ElfParser`].
    pub(crate) fn parser(&self) -> &ElfParser {
        match self {
            #[cfg(feature = "dwarf")]
            Self::Dwarf(resolver) => resolver.parser(),
            Self::Elf(parser) => parser,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "dwarf")]
impl ElfBackend {
    pub fn to_dwarf(&self) -> Option<&DwarfResolver> {
        if let Self::Dwarf(dwarf) = self {
            Some(dwarf)
        } else {
            None
        }
    }

    pub fn is_dwarf(&self) -> bool {
        matches!(self, Self::Dwarf(_))
    }
}


#[derive(Debug)]
pub(crate) struct ElfCacheEntry<T> {
    dev: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    mtime_sec: libc::time_t,
    mtime_nsec: i64,
    pub value: T,
}

impl<T> ElfCacheEntry<T> {
    fn new(stat: &libc::stat, value: T) -> Self {
        Self {
            dev: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            mtime_sec: stat.st_mtime,
            mtime_nsec: stat.st_mtime_nsec,
            value,
        }
    }

    fn is_current(&self, stat: &libc::stat) -> bool {
        stat.st_dev == self.dev
            && stat.st_ino == self.inode
            && stat.st_size == self.size
            && stat.st_mtime == self.mtime_sec
            && stat.st_mtime_nsec == self.mtime_nsec
    }
}


#[derive(Debug)]
pub(crate) struct ElfCache {
    cache: HashMap<PathBuf, ElfCacheEntry<ElfBackend>>,
    line_number_info: bool,
    debug_info_symbols: bool,
}

impl ElfCache {
    pub fn new(line_number_info: bool, debug_info_symbols: bool) -> Self {
        Self {
            cache: HashMap::new(),
            line_number_info,
            debug_info_symbols,
        }
    }

    fn create_entry(
        stat: &libc::stat,
        file: File,
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<ElfCacheEntry<ElfBackend>> {
        let parser = Rc::new(ElfParser::open_file(&file)?);
        #[cfg(feature = "dwarf")]
        let backend = ElfBackend::Dwarf(Rc::new(DwarfResolver::from_parser(
            Rc::clone(&parser),
            line_number_info,
            debug_info_symbols,
        )?));

        #[cfg(not(feature = "dwarf"))]
        let backend = ElfBackend::Elf(parser);
        let entry = ElfCacheEntry::new(stat, backend);
        Ok(entry)
    }

    pub fn find(&mut self, path: &Path) -> Result<&ElfCacheEntry<ElfBackend>> {
        let file =
            File::open(path).with_context(|| format!("failed to open file {}", path.display()))?;
        let stat = fstat(file.as_raw_fd())?;

        match self.cache.entry(path.to_path_buf()) {
            hash_map::Entry::Occupied(mut occupied) => {
                if occupied.get().is_current(&stat) {
                    return Ok(occupied.into_mut())
                }
                let entry = Self::create_entry(
                    &stat,
                    file,
                    self.line_number_info,
                    self.debug_info_symbols,
                )?;
                let _old = occupied.insert(entry);
                Ok(occupied.into_mut())
            }
            hash_map::Entry::Vacant(vacancy) => {
                let entry = Self::create_entry(
                    &stat,
                    file,
                    self.line_number_info,
                    self.debug_info_symbols,
                )?;
                let entry = vacancy.insert(entry);
                Ok(entry)
            }
        }
    }

    #[inline]
    pub fn debug_syms(&self) -> bool {
        self.debug_info_symbols
    }

    #[inline]
    pub fn code_info(&self) -> bool {
        self.line_number_info
    }
}


#[cfg(test)]
#[cfg(feature = "dwarf")]
mod tests {
    use super::*;

    use std::env;
    use std::ptr;

    use test_log::test;

    #[test]
    fn test_cache() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let code_info = true;
        let debug_syms = false;
        let mut cache = ElfCache::new(code_info, debug_syms);
        let backend_first = cache.find(Path::new(&bin_name)).unwrap().value.clone();
        let backend_second = cache.find(Path::new(&bin_name)).unwrap().value.clone();
        assert!(backend_first.is_dwarf());
        assert!(backend_second.is_dwarf());
        assert_eq!(
            ptr::addr_of!(*backend_first.to_dwarf().unwrap().parser()),
            ptr::addr_of!(*backend_second.to_dwarf().unwrap().parser())
        );
    }
}

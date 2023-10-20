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


#[derive(Debug)]
struct ElfCacheEntry<T> {
    dev: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    mtime_sec: libc::time_t,
    mtime_nsec: i64,
    file: File,
    value: Option<T>,
}

impl<T> ElfCacheEntry<T> {
    fn new(stat: &libc::stat, file: File) -> Self {
        Self {
            dev: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            mtime_sec: stat.st_mtime,
            mtime_nsec: stat.st_mtime_nsec,
            file,
            value: None,
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
pub(crate) struct ElfCache<T> {
    cache: HashMap<PathBuf, ElfCacheEntry<T>>,
}

impl<T> ElfCache<T> {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn entry(&mut self, path: &Path) -> Result<(&File, &mut Option<T>)> {
        let file =
            File::open(path).with_context(|| format!("failed to open file {}", path.display()))?;
        let stat = fstat(file.as_raw_fd())?;

        match self.cache.entry(path.to_path_buf()) {
            hash_map::Entry::Occupied(mut occupied) => {
                if occupied.get().is_current(&stat) {
                    let entry = occupied.into_mut();
                    return Ok((&entry.file, &mut entry.value))
                }
                let entry = ElfCacheEntry::new(&stat, file);
                let _old = occupied.insert(entry);
                let entry = occupied.into_mut();
                Ok((&entry.file, &mut entry.value))
            }
            hash_map::Entry::Vacant(vacancy) => {
                let entry = ElfCacheEntry::new(&stat, file);
                let entry = vacancy.insert(entry);
                Ok((&entry.file, &mut entry.value))
            }
        }
    }
}

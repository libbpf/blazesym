use std::cell::OnceCell;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;

use crate::insert_map::InsertMap;
use crate::util::fstat;
use crate::ErrorExt as _;
use crate::Result;


#[derive(Debug, Eq, Hash, PartialEq)]
struct EntryMeta {
    path: PathBuf,
    dev: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    mtime_sec: libc::time_t,
    mtime_nsec: i64,
}

impl EntryMeta {
    fn new(path: PathBuf, stat: &libc::stat) -> Self {
        Self {
            path,
            dev: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            mtime_sec: stat.st_mtime,
            mtime_nsec: stat.st_mtime_nsec,
        }
    }
}


#[derive(Debug)]
struct Entry<T> {
    file: File,
    value: OnceCell<T>,
}

impl<T> Entry<T> {
    fn new(file: File) -> Self {
        Self {
            file,
            value: OnceCell::new(),
        }
    }
}


#[derive(Debug)]
pub(crate) struct FileCache<T> {
    cache: InsertMap<EntryMeta, Entry<T>>,
}

impl<T> FileCache<T> {
    pub fn new() -> Self {
        Self {
            cache: InsertMap::new(),
        }
    }

    pub fn entry(&self, path: &Path) -> Result<(&File, &OnceCell<T>)> {
        let file =
            File::open(path).with_context(|| format!("failed to open file {}", path.display()))?;
        let stat = fstat(file.as_raw_fd())?;
        let meta = EntryMeta::new(path.to_path_buf(), &stat);

        let entry = self.cache.get_or_insert(meta, || Entry::new(file));
        Ok((&entry.file, &entry.value))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read as _;
    use std::io::Write as _;
    use std::thread::sleep;
    use std::time::Duration;

    use tempfile::tempfile;
    use tempfile::NamedTempFile;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let cache = FileCache::<()>::new();
        assert_ne!(format!("{cache:?}"), "");

        let tmpfile = tempfile().unwrap();
        let entry = Entry::<usize>::new(tmpfile);
        assert_ne!(format!("{entry:?}"), "");
    }

    /// Check that we can associate data with a file.
    #[test]
    fn lookup() {
        let cache = FileCache::<usize>::new();
        let tmpfile = NamedTempFile::new().unwrap();

        {
            let (_file, cell) = cache.entry(tmpfile.path()).unwrap();
            assert_eq!(cell.get(), None);

            let () = cell.set(42).unwrap();
        }

        {
            let (_file, cell) = cache.entry(tmpfile.path()).unwrap();
            assert_eq!(cell.get(), Some(&42));
        }
    }

    /// Make sure that a changed file purges the cache entry.
    #[test]
    fn outdated() {
        let cache = FileCache::<usize>::new();
        let tmpfile = NamedTempFile::new().unwrap();
        let modified = {
            let (file, cell) = cache.entry(tmpfile.path()).unwrap();
            assert_eq!(cell.get(), None);

            let () = cell.set(42).unwrap();
            file.metadata().unwrap().modified().unwrap()
        };

        // Sleep briefly to make sure that file times will end up being
        // different.
        let () = sleep(Duration::from_millis(10));

        let mut file = File::create(tmpfile.path()).unwrap();
        let () = file.write_all(b"foobar").unwrap();

        {
            let (mut file, entry) = cache.entry(tmpfile.path()).unwrap();
            assert_eq!(entry.get(), None);
            assert_ne!(file.metadata().unwrap().modified().unwrap(), modified);

            let mut content = Vec::new();
            let _count = file.read_to_end(&mut content);
            assert_eq!(content, b"foobar");
        }
    }
}

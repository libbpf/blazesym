use std::cell::Cell;
use std::fs::File;
use std::marker::PhantomData;
use std::path::Path;
use std::path::PathBuf;

use crate::insert_map::InsertMap;
use crate::once::OnceCell;
use crate::util::stat;
use crate::ErrorExt as _;
use crate::Result;


#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
// `libc` has deprecated `time_t` usage on `musl`. See
// https://github.com/rust-lang/libc/issues/1848
#[cfg_attr(target_env = "musl", allow(deprecated))]
struct FileMeta {
    dev: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    mtime_sec: libc::time_t,
    #[cfg(linux)]
    mtime_nsec: i64,
}

impl From<&libc::stat> for FileMeta {
    fn from(other: &libc::stat) -> Self {
        // Casts are necessary because on Android some libc types do not
        // use proper typedefs. https://github.com/rust-lang/libc/issues/3285
        #[allow(trivial_numeric_casts)]
        Self {
            dev: other.st_dev as _,
            inode: other.st_ino as _,
            size: other.st_size as _,
            mtime_sec: other.st_mtime,
            #[cfg(linux)]
            mtime_nsec: other.st_mtime_nsec as _,
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


#[derive(Clone, Copy, Debug, PartialEq)]
enum PinState {
    Pinned,
    Unpinned,
}

#[derive(Debug)]
struct PathEntry {
    /// Meta data corresponding to the most recently inserted entry.
    current: Cell<Option<(PinState, FileMeta)>>,
}

impl Default for PathEntry {
    fn default() -> Self {
        Self {
            current: Cell::new(None),
        }
    }
}


/// A builder for configurable construction of [`FileCache`] objects.
///
/// By default all features are enabled.
#[derive(Clone, Debug)]
pub(crate) struct Builder<T> {
    /// Whether or not to automatically reload files that were updated
    /// since the last open.
    auto_reload: bool,
    /// Phantom data for our otherwise "unused" generic argument.
    _phantom: PhantomData<T>,
}

impl<T> Builder<T> {
    /// Enable/disable auto reloading of files when stale.
    pub(crate) fn enable_auto_reload(mut self, enable: bool) -> Self {
        self.auto_reload = enable;
        self
    }

    /// Create the [`FileCache`] object.
    pub(crate) fn build(self) -> FileCache<T> {
        let Builder {
            auto_reload,
            _phantom: _,
        } = self;

        FileCache {
            cache: InsertMap::new(),
            entries: InsertMap::new(),
            auto_reload,
        }
    }
}

impl<T> Default for Builder<T> {
    fn default() -> Self {
        Self {
            auto_reload: true,
            _phantom: PhantomData,
        }
    }
}


/// A lookup cache for data associated with a file, looked up by path.
///
/// The cache transparently checks whether the file contents have
/// changed based on file system meta data and creates and hands out a
/// new entry if so.
/// Note that stale/old entries are never evicted.
#[derive(Debug)]
pub(crate) struct FileCache<T> {
    /// The map we use for associating a path with file meta data.
    cache: InsertMap<PathBuf, PathEntry>,
    /// The map of entries.
    entries: InsertMap<FileMeta, Entry<T>>,
    /// Whether or not to automatically reload files that were updated
    /// since the last open.
    auto_reload: bool,
}

impl<T> FileCache<T> {
    /// Retrieve a [`Builder`] object for configurable construction of a
    /// [`FileCache`].
    pub(crate) fn builder() -> Builder<T> {
        Builder::<T>::default()
    }

    fn get_or_insert(&self, path: &Path, path_entry: &PathEntry) -> Result<&Entry<T>> {
        let stat = stat(path).with_context(|| format!("failed to stat `{}`", path.display()))?;
        let meta = (PinState::Unpinned, FileMeta::from(&stat));

        let entry = self.entries.get_or_try_insert(meta.1, || {
            // We may end up associating this file with a potentially
            // outdated `stat` (which could have changed), but the only
            // consequence is that we'd create a new entry again in the
            // future. On the bright side, we save one `stat` call.
            let file = File::open(path)
                .with_context(|| format!("failed to open file `{}`", path.display()))?;
            let entry = Entry::new(file);
            Ok(entry)
        })?;
        let () = path_entry.current.set(Some(meta));

        Ok(entry)
    }

    /// Retrieve the entry for the file at the given `path`.
    pub(crate) fn entry(&self, path: &Path) -> Result<(&File, &OnceCell<T>)> {
        let path_entry = self
            .cache
            .get_or_insert(path.to_path_buf(), PathEntry::default);
        if let Some((pin_state, current_meta)) = path_entry.current.get() {
            if !self.auto_reload || pin_state == PinState::Pinned {
                // SANITY: Our invariant states that if there is a
                //         `PathEntry::current` a corresponding entry
                //         must be in `FileCache::entries`.
                let current = self.entries.get(&current_meta).unwrap();
                return Ok((&current.file, &current.value))
            }
        }

        let entry = self.get_or_insert(path, path_entry)?;
        Ok((&entry.file, &entry.value))
    }

    fn set_pin_state(&self, path: &Path, pin_state: PinState) -> Option<()> {
        let path_entry = self.cache.get(path)?;
        let current = path_entry.current.get()?;
        let () = path_entry.current.set(Some((pin_state, current.1)));
        Some(())
    }

    /// Pin the entry for the file at the given `path`.
    ///
    /// A pinned entry is one on which no auto reloading will take place
    /// and it will supersede any unpinned entries already available
    /// (i.e., it acts as the most recent entry moving forward until
    /// unpinned).
    pub(crate) fn pin(&self, path: &Path) -> Option<()> {
        self.set_pin_state(path, PinState::Pinned)
    }

    pub(crate) fn unpin(&self, path: &Path) -> Option<()> {
        self.set_pin_state(path, PinState::Unpinned)
    }

    /// Retrieve the total number of entries in the cache.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl<T> Default for FileCache<T> {
    fn default() -> Self {
        Self::builder().build()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(linux)]
    use std::fs::remove_file;
    use std::fs::write;
    #[cfg(feature = "nightly")]
    use std::hint::black_box;
    use std::io::Read as _;
    #[cfg(linux)]
    use std::os::fd::AsRawFd as _;
    #[cfg(linux)]
    use std::os::unix::fs::symlink;
    use std::thread::sleep;
    use std::time::Duration;

    use tempfile::tempdir;
    use tempfile::tempfile;
    use tempfile::NamedTempFile;

    #[cfg(feature = "nightly")]
    use test::Bencher;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let cache = FileCache::<()>::default();
        assert_ne!(format!("{cache:?}"), "");

        let tmpfile = tempfile().unwrap();
        let entry = Entry::<usize>::new(tmpfile);
        assert_ne!(format!("{entry:?}"), "");
    }

    /// Check that we can associate data with a file.
    #[test]
    fn lookup() {
        let cache = FileCache::<usize>::default();
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

    /// Check that our `FileCache` deduplicates symbolic link targets
    /// properly.
    #[cfg(linux)]
    #[test]
    fn symlink_entries() {
        let tmpfile = NamedTempFile::new().unwrap();
        let tmpdir = tempdir().unwrap();
        let link = tmpdir.path().join("symlink");
        let () = symlink(tmpfile.path(), &link).unwrap();

        let cache = FileCache::<usize>::default();
        let (file1, cell) = cache.entry(tmpfile.path()).unwrap();
        let () = cell.set(42).unwrap();

        // The entry for the link should reference the targeted file.
        let (file2, cell) = cache.entry(&link).unwrap();
        assert_eq!(cell.get(), Some(&42));
        assert_eq!(file2.as_raw_fd(), file1.as_raw_fd());

        // Now replace the link with a proper file. This file should
        // subsequently get picked up.
        let () = remove_file(&link).unwrap();
        let () = write(&link, b"test").unwrap();
        let (file3, cell) = cache.entry(&link).unwrap();
        assert_eq!(cell.get(), None);
        assert_ne!(file3.as_raw_fd(), file1.as_raw_fd());

        // But of course the original entry should still exist.
        let (file4, cell) = cache.entry(tmpfile.path()).unwrap();
        assert_eq!(cell.get(), Some(&42));
        assert_eq!(file4.as_raw_fd(), file1.as_raw_fd());
    }

    /// Make sure that symbolic link chain updates are picked up.
    #[cfg(linux)]
    #[test]
    fn multi_symlink_reload() {
        // We create the following symbolic link setup:
        //   link1 -> link2 -> file
        let tmpfile = NamedTempFile::new().unwrap();
        let tmpdir = tempdir().unwrap();
        let link2 = tmpdir.path().join("symlink2");
        let () = symlink(tmpfile.path(), &link2).unwrap();
        let link1 = tmpdir.path().join("symlink1");
        let () = symlink(&link2, &link1).unwrap();

        let cache = FileCache::<usize>::default();
        let (file1, cell) = cache.entry(&link1).unwrap();
        let () = cell.set(41).unwrap();

        // Now replace `link2` with a link to a different file.
        let tmpfile2 = NamedTempFile::new().unwrap();
        let () = remove_file(&link2).unwrap();
        let () = symlink(tmpfile2.path(), &link2).unwrap();

        // Our `FileCache` should pick up the change and create a new
        // entry.
        let (file2, cell) = cache.entry(&link1).unwrap();
        assert_eq!(cell.get(), None);
        assert_ne!(file2.as_raw_fd(), file1.as_raw_fd());
    }

    /// Check pinning works correctly in the presence of symbolic links.
    #[cfg(linux)]
    #[test]
    fn symlink_pinning() {
        let tmpfile = NamedTempFile::new().unwrap();
        let tmpdir = tempdir().unwrap();
        let link = tmpdir.path().join("symlink");
        let () = symlink(tmpfile.path(), &link).unwrap();

        let cache = FileCache::<usize>::default();
        let (file1, cell) = cache.entry(&link).unwrap();
        let () = cell.set(42).unwrap();

        let () = cache.pin(&link).unwrap();

        // Update symbolic link to point to new file.
        let tmpfile2 = NamedTempFile::new().unwrap();
        let () = remove_file(&link).unwrap();
        let () = symlink(tmpfile2.path(), &link).unwrap();

        // We should still see the pinned content.
        let (file2, cell) = cache.entry(&link).unwrap();
        assert_eq!(cell.get(), Some(&42));
        assert_eq!(file2.as_raw_fd(), file1.as_raw_fd());

        // Update the target file as well and check again.
        let () = write(tmpfile.path(), b"new-content").unwrap();
        let (file3, cell) = cache.entry(&link).unwrap();
        assert_eq!(cell.get(), Some(&42));
        assert_eq!(file3.as_raw_fd(), file1.as_raw_fd());
    }

    /// Check that the `FileCache` reports the expected error when
    /// encountering a symbolic link that points to a non-existent
    /// target.
    #[cfg(linux)]
    #[test]
    fn symlink_dead_target() {
        let tmpfile = NamedTempFile::new().unwrap();
        let tmpdir = tempdir().unwrap();
        let link = tmpdir.path().join("symlink");
        let () = symlink(tmpfile.path(), &link).unwrap();
        let () = tmpfile.close().unwrap();

        let cache = FileCache::<usize>::default();
        let err = cache.entry(&link).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// Make sure that a changed file updates the cache entry.
    #[test]
    fn outdated() {
        fn test(auto_reload: bool, pin: bool) {
            let cache = FileCache::<usize>::builder()
                .enable_auto_reload(auto_reload)
                .build();
            let tmpfile = NamedTempFile::new().unwrap();
            let modified = {
                let (file, cell) = cache.entry(tmpfile.path()).unwrap();
                if pin {
                    let () = cache.pin(tmpfile.path()).unwrap();
                }
                assert_eq!(cell.get(), None);

                let () = cell.set(42).unwrap();
                file.metadata().unwrap().modified().unwrap()
            };

            // Sleep briefly to make sure that file times will end up being
            // different.
            let () = sleep(Duration::from_millis(10));

            let path = tmpfile.path().to_path_buf();
            let () = drop(tmpfile);

            {
                let () = write(&path, b"foobar").unwrap();
            }

            {
                let (mut file, entry) = cache.entry(&path).unwrap();

                if auto_reload && !pin {
                    let new_modified = file.metadata().unwrap().modified().unwrap();
                    assert_eq!(entry.get(), None);
                    assert!(new_modified > modified, "{new_modified:?} | {modified:?}");

                    let mut content = Vec::new();
                    let _count = file.read_to_end(&mut content);
                    assert_eq!(content, b"foobar");
                } else {
                    assert_eq!(entry.get(), Some(&42));
                    assert_eq!(file.metadata().unwrap().modified().unwrap(), modified);
                }
            }
        }

        for auto_reload in [false, true] {
            for pin in [false, true] {
                let () = test(auto_reload, pin);
            }
        }
    }

    /// Check that a removed file poses no problem if associated data
    /// had been pinned.
    #[test]
    fn removed() {
        #[track_caller]
        fn test(pin: bool) {
            let tmpfile = NamedTempFile::new().unwrap();
            let cache = FileCache::<usize>::builder().build();
            let (_file, cell) = cache.entry(tmpfile.path()).unwrap();
            if pin {
                let () = cache.pin(tmpfile.path()).unwrap();
            }
            let () = cell.set(42).unwrap();

            let path = tmpfile.path().to_path_buf();
            let () = drop(tmpfile);

            let result = cache.entry(&path);
            if pin {
                let (_file, cell) = result.unwrap();
                assert_eq!(cell.get(), Some(&42));
            } else {
                let err = result.unwrap_err();
                assert_eq!(err.kind(), ErrorKind::NotFound);
            }
        }

        for pin in [false, true] {
            let () = test(pin);
        }
    }

    #[cfg(feature = "nightly")]
    fn bench_entry_retrieval_no_change_impl(b: &mut Bencher, pin: bool) {
        let tmpfile = NamedTempFile::new().unwrap();
        let path = tmpfile.path();
        let cache = FileCache::<usize>::builder().build();
        let (_file, cell) = cache.entry(path).unwrap();
        if pin {
            let () = cache.pin(path).unwrap();
        }
        let () = cell.set(42).unwrap();

        let () = b.iter(|| {
            let entry = cache.entry(&path).unwrap();
            let _entry = black_box(entry);
        });
    }

    /// Benchmark the (best case) retrieval of a `FileCache` entry with
    /// only a single entry in it.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_entry_retrieval_no_change(b: &mut Bencher) {
        let pin = false;
        bench_entry_retrieval_no_change_impl(b, pin)
    }

    /// Benchmark the (best case) retrieval of a `FileCache` entry with
    /// only a single pinned entry in it.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_entry_retrieval_no_change_pinned(b: &mut Bencher) {
        let pin = true;
        bench_entry_retrieval_no_change_impl(b, pin)
    }
}

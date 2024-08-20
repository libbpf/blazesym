use std::fs::File;
use std::ops::Deref;
use std::ops::Range;
use std::path::Path;
use std::rc::Rc;

use memmap2::Mmap as Mapping;
use memmap2::MmapOptions;

use crate::Error;
use crate::ErrorExt as _;
use crate::Result;


#[derive(Debug)]
pub(crate) struct Builder {
    exec: bool,
}

impl Builder {
    fn new() -> Self {
        Self { exec: false }
    }

    /// Configure the mapping to be executable.
    #[cfg(test)]
    pub(crate) fn exec(mut self) -> Self {
        self.exec = true;
        self
    }

    /// Memory map the file at the provided `path`.
    pub(crate) fn open<P>(self, path: P) -> Result<Mmap>
    where
        P: AsRef<Path>,
    {
        let file = File::open(path)?;
        self.map(&file)
    }

    /// Map the provided file into memory, in its entirety.
    pub(crate) fn map(self, file: &File) -> Result<Mmap> {
        let len = libc::size_t::try_from(file.metadata()?.len())
            .map_err(Error::with_invalid_data)
            .context("file is too large to mmap")?;

        // The kernel does not allow mmap'ing a region of size 0. We
        // want to enable this case transparently, though.
        let mmap = if len == 0 {
            Mmap {
                mapping: None,
                view: 0..1,
            }
        } else {
            let opts = MmapOptions::new();

            let mapping = if self.exec {
                unsafe { opts.map_exec(file) }
            } else {
                unsafe { opts.map(file) }
            }?;

            Mmap {
                mapping: Some(Rc::new(mapping)),
                view: 0..len as u64,
            }
        };
        Ok(mmap)
    }
}


/// A type encapsulating a region of mapped memory.
#[derive(Clone, Debug)]
pub struct Mmap {
    /// The actual memory mapping.
    mapping: Option<Rc<Mapping>>,
    /// The view on the memory mapping that this object represents.
    view: Range<u64>,
}

impl Mmap {
    /// Create [`Builder`] for creating a customizable memory mapping.
    pub(crate) fn builder() -> Builder {
        Builder::new()
    }

    /// Map the provided file into memory, in its entirety.
    pub(crate) fn map(file: &File) -> Result<Self> {
        Self::builder().map(file)
    }

    /// Create a new `Mmap` object (sharing the same underlying memory mapping
    /// as the current one) that restricts its view to the provided `range`.
    /// Adjustment happens relative to the current view.
    pub(crate) fn constrain(&self, range: Range<u64>) -> Option<Self> {
        if self.view.start + range.end > self.view.end {
            return None
        }

        let mut mmap = self.clone();
        mmap.view.end = mmap.view.start + range.end;
        mmap.view.start += range.start;
        Some(mmap)
    }
}

impl Deref for Mmap {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        if let Some(mapping) = &self.mapping {
            mapping
                .deref()
                .get(self.view.start as usize..self.view.end as usize)
                .unwrap_or(&[])
        } else {
            &[]
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CStr;
    use std::io::Write;

    use tempfile::NamedTempFile;
    use test_log::test;

    use crate::util::ReadRaw;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let builder = Builder::new();
        assert_ne!(format!("{builder:?}"), "");
    }

    /// Check that we can `mmap` an empty file.
    #[test]
    fn mmap_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let file = file.as_file();
        let mmap = Mmap::map(file).unwrap();
        assert_eq!(mmap.deref(), &[]);
    }

    /// Check that we can `mmap` a file.
    #[test]
    fn mmap() {
        let file = NamedTempFile::new().unwrap();
        let mut file = file.as_file();
        let cstr = b"Daniel was here. Briefly.\0";
        let () = file.write_all(cstr).unwrap();
        let () = file.sync_all().unwrap();

        let mmap = Mmap::map(file).unwrap();
        let mut data = mmap.deref();
        let s = data.read_cstr().unwrap();
        assert_eq!(
            s.to_str().unwrap(),
            CStr::from_bytes_with_nul(cstr).unwrap().to_str().unwrap()
        );
    }

    /// Check that we can properly restrict the view of a `Mmap`.
    #[test]
    fn view_constraining() {
        let file = NamedTempFile::new().unwrap();
        let mut file = file.as_file();
        let s = b"abcdefghijklmnopqrstuvwxyz";
        let () = file.write_all(s).unwrap();
        let () = file.sync_all().unwrap();

        let mmap = Mmap::map(file).unwrap();
        assert_eq!(mmap.deref(), b"abcdefghijklmnopqrstuvwxyz");

        let mmap = mmap.constrain(1..15).unwrap();
        assert_eq!(mmap.deref(), b"bcdefghijklmno");

        let mmap = mmap.constrain(5..6).unwrap();
        assert_eq!(mmap.deref(), b"g");

        assert!(mmap.constrain(1..2).is_none());
    }
}

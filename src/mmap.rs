use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::ops::Deref;
use std::ops::Range;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::null_mut;
use std::rc::Rc;
use std::slice;


#[derive(Debug)]
pub(crate) struct Builder {
    /// The protection flags to use.
    protection: libc::c_int,
}

impl Builder {
    fn new() -> Self {
        Self {
            protection: libc::PROT_READ,
        }
    }

    /// Configure the mapping to be executable.
    #[cfg(test)]
    pub fn exec(mut self) -> Self {
        self.protection |= libc::PROT_EXEC;
        self
    }

    /// Memory map the file at the provided `path`.
    pub fn open<P>(self, path: P) -> Result<Mmap>
    where
        P: AsRef<Path>,
    {
        let file = File::open(path)?;
        self.map(&file)
    }

    /// Map the provided file into memory, in its entirety.
    pub fn map(self, file: &File) -> Result<Mmap> {
        let len = libc::size_t::try_from(file.metadata()?.len())
            .map_err(|_err| Error::new(ErrorKind::InvalidData, "file is too large to mmap"))?;
        let offset = 0;

        // SAFETY: `mmap` with the provided arguments is always safe to call.
        let ptr = unsafe {
            libc::mmap(
                null_mut(),
                len,
                self.protection,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                offset,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(Error::last_os_error())
        }

        let mapping = Mapping { ptr, len };
        let mmap = Mmap {
            mapping: Rc::new(mapping),
            view: 0..len,
        };
        Ok(mmap)
    }
}


#[derive(Debug)]
pub(crate) struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Deref for Mapping {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know that the pointer is valid and represents a region of
        //         `len` bytes.
        unsafe { slice::from_raw_parts(self.ptr.cast(), self.len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: The `ptr` is valid.
        let rc = unsafe { libc::munmap(self.ptr, self.len) };
        assert!(rc == 0, "unable to unmap mmap: {}", Error::last_os_error());
    }
}


#[derive(Clone, Debug)]
pub(crate) struct Mmap {
    /// The actual memory mapping.
    mapping: Rc<Mapping>,
    /// The view on the memory mapping that this object represents.
    view: Range<usize>,
}

impl Mmap {
    /// Create [`Builder`] for creating a customizable memory mapping.
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// Map the provided file into memory, in its entirety.
    pub fn map(file: &File) -> Result<Self> {
        Self::builder().map(file)
    }

    /// Create a new `Mmap` object (sharing the same underlying memory mapping
    /// as the current one) that restricts its view to the provided `range`.
    /// Adjustment happens relative to the current view.
    #[cfg(test)]
    pub fn constrain(&self, range: Range<usize>) -> Option<Self> {
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
        self.mapping.deref().get(self.view.clone()).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CStr;
    use std::io::Write;

    use tempfile::tempfile;
    use test_log::test;

    use crate::util::ReadRaw;


    /// Check that we can `mmap` a file.
    #[test]
    fn mmap() {
        let mut file = tempfile().unwrap();
        let cstr = b"Daniel was here. Briefly.\0";
        let () = file.write_all(cstr).unwrap();
        let () = file.sync_all().unwrap();

        let mmap = Mmap::map(&file).unwrap();
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
        let mut file = tempfile().unwrap();
        let s = b"abcdefghijklmnopqrstuvwxyz";
        let () = file.write_all(s).unwrap();
        let () = file.sync_all().unwrap();

        let mmap = Mmap::map(&file).unwrap();
        assert_eq!(mmap.deref(), b"abcdefghijklmnopqrstuvwxyz");

        let mmap = mmap.constrain(1..15).unwrap();
        assert_eq!(mmap.deref(), b"bcdefghijklmno");

        let mmap = mmap.constrain(5..6).unwrap();
        assert_eq!(mmap.deref(), b"g");

        assert!(mmap.constrain(1..2).is_none());
    }
}

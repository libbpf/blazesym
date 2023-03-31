use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::slice;

#[derive(Debug)]
pub(crate) struct Mmap {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Mmap {
    pub fn map(file: &File) -> Result<Self, Error> {
        let len = libc::size_t::try_from(file.metadata()?.len())
            .map_err(|_err| Error::new(ErrorKind::InvalidData, "file is too large to mmap"))?;
        let offset = 0;

        // SAFETY: `mmap` with the provided arguments is always safe to call.
        let ptr = unsafe {
            libc::mmap(
                null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                offset,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(Error::last_os_error())
        }

        let slf = Mmap { ptr, len };
        Ok(slf)
    }
}

impl Deref for Mmap {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know that the pointer is valid and represents a region of
        //         `len` bytes.
        unsafe { slice::from_raw_parts(self.ptr.cast(), self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: The `ptr` is valid.
        let rc = unsafe { libc::munmap(self.ptr, self.len) };
        assert!(rc == 0, "unable to unmap mmap: {}", Error::last_os_error());
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
}

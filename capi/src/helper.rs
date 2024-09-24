use std::ffi::c_char;
use std::ffi::CStr;
use std::ptr;

use blazesym::BuildId;
use blazesym::__private::bytes_to_path;
use blazesym::helper::is_procmap_query_supported;
use blazesym::helper::read_elf_build_id;
use blazesym::Result;

use crate::blaze_err;
#[cfg(doc)]
use crate::blaze_err_last;
use crate::set_last_err;


/// Check whether the `PROCMAP_QUERY` ioctl is supported by the system.
///
/// This function returns `true` if the system supports the
/// `PROCMAP_QUERY` ioctl and `false` in all other cases, including when
/// an error occurred. Use [`blaze_err_last`] to optionally retrieve
/// this error.
#[no_mangle]
pub extern "C" fn blaze_supports_procmap_query() -> bool {
    let result = is_procmap_query_supported();
    let err = result
        .as_ref()
        .map(|_| blaze_err::BLAZE_ERR_OK)
        .unwrap_or_else(|err| err.kind().into());
    let () = set_last_err(err);
    result.unwrap_or(false)
}

/// Read the build ID of an ELF file located at the given path.
///
/// Build IDs can have variable length, depending on which flavor is
/// used (e.g., 20 bytes for `sha1` flavor). Build IDs are
/// reported as "raw" bytes. If you need a hexadecimal representation as
/// reported by tools such as `readelf(1)`, a post processing step is
/// necessary.
///
/// On success and when a build ID present, the function returns a
/// pointer to the "raw" build ID bytes and `len`, if provided, is set
/// to the build ID's length. The resulting buffer should be released
/// using libc's `free` function once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last
/// error to indicate the problem encountered. Use [`blaze_err_last`] to
/// retrieve this error.
///
/// Similarly, if no build ID is present `NULL` is returned and the last
/// error will be set to [`BLAZE_ERR_OK`][blaze_err::BLAZE_ERR_OK].
///
/// # Safety
/// - `path` needs to be a valid pointer to a NUL terminated string
#[no_mangle]
pub unsafe extern "C" fn blaze_read_elf_build_id(path: *const c_char, len: *mut usize) -> *mut u8 {
    #[inline]
    fn inner(path: *const c_char, len: *mut usize) -> Result<Option<BuildId<'static>>> {
        // SAFETY: The caller is required to pass in a valid pointer.
        let path = unsafe { CStr::from_ptr(path) };
        let path = bytes_to_path(path.to_bytes())?;
        let build_id = read_elf_build_id(path)?;
        if !len.is_null() {
            // SAFETY: If `len` is not `NULL`, the caller must ensure
            //         that it points to valid writable memory.
            let () = unsafe {
                len.write(
                    build_id
                        .as_ref()
                        .map(|build_id| build_id.len())
                        .unwrap_or_default(),
                )
            };
        }
        Ok(build_id)
    }

    let result = inner(path, len);
    let err = result
        .as_ref()
        .map(|_| blaze_err::BLAZE_ERR_OK)
        .unwrap_or_else(|err| err.kind().into());
    let () = set_last_err(err);

    // NB: We don't specify what `len` is set to in case of
    //     error, so we don't even attempt to change it below.

    match result {
        Ok(None) | Err(..) => ptr::null_mut(),
        Ok(Some(build_id)) => {
            let len = build_id.len();
            // SAFETY: `malloc` is always safe to call.
            let dst = unsafe { libc::malloc(len) }.cast::<u8>();
            if dst.is_null() {
                let () = set_last_err(blaze_err::BLAZE_ERR_OUT_OF_MEMORY);
            } else {
                // SAFETY: `build_id` is trivially valid and `dst` is
                //         coming from a `malloc` already checked for
                //         `NULL`; hence, it is valid as well here. Both
                //         buffers are `len` bytes in size.
                let () = unsafe { ptr::copy_nonoverlapping(build_id.as_ptr(), dst, len) };
            }
            dst
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::path::Path;
    use std::slice;

    use crate::blaze_err;
    use crate::blaze_err_last;


    /// Test that we can check whether the `PROCMAP_QUERY` ioctl is
    /// supported.
    #[test]
    fn procmap_query_supported() {
        let _supported = blaze_supports_procmap_query();
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_OK);
    }

    /// Check that we can read a binary's build ID.
    #[test]
    fn build_id_reading() {
        let mut len = 0;
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("libtest-so.so");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let build_id = unsafe { blaze_read_elf_build_id(path_c.as_ptr(), &mut len) };
        assert!(!build_id.is_null());
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_OK);
        // The file contains a sha1 build ID, which is always 20 bytes in length.
        assert_eq!(len, 20);

        // Also smoke test that the build ID equals what the Rust API
        // reports.
        let build_id_rs = read_elf_build_id(&path).unwrap().unwrap();
        assert_eq!(
            unsafe { slice::from_raw_parts(build_id, len) },
            &*build_id_rs
        );
        let () = unsafe { libc::free(build_id.cast()) };

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("libtest-so-no-separate-code.so");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let build_id = unsafe { blaze_read_elf_build_id(path_c.as_ptr(), &mut len) };
        assert!(!build_id.is_null());
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_OK);
        // The file contains an md5 build ID, which is always 16 bytes long.
        assert_eq!(len, 16);
        let () = unsafe { libc::free(build_id.cast()) };

        // The shared object is explicitly built without build ID.
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-no-debug.bin");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let build_id = unsafe { blaze_read_elf_build_id(path_c.as_ptr(), &mut len) };
        assert!(build_id.is_null());
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_OK);

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("does-not-exist");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let build_id = unsafe { blaze_read_elf_build_id(path_c.as_ptr(), &mut len) };
        assert!(build_id.is_null());
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_NOT_FOUND);
    }
}

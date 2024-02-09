#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::env::current_exe;
use std::io::Error;
use std::io::Result;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt as _;
use std::panic::catch_unwind;
use std::panic::UnwindSafe;
use std::path::Path;

use libc::seteuid;
use libc::uid_t;


/// Run a function with a different effective user ID.
pub fn as_user<F, R>(ruid: uid_t, euid: uid_t, f: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    if unsafe { seteuid(euid) } == -1 {
        panic!(
            "failed to set effective user ID to {euid}: {}",
            Error::last_os_error()
        )
    }

    let result = catch_unwind(f);

    // Make sure that we restore the real user before tearing down,
    // because shut down code may need the original permissions (e.g., for
    // writing down code coverage files or similar.
    if unsafe { seteuid(ruid) } == -1 {
        panic!(
            "failed to restore effective user ID to {ruid}: {}",
            Error::last_os_error()
        )
    }

    result.unwrap()
}


// TODO: Copy of logic from the main crate. If usage proliferates we
//       should think of a way to share.
fn stat(path: &Path) -> Result<libc::stat> {
    let mut dst = MaybeUninit::uninit();
    let mut path = path.as_os_str().as_bytes().to_vec();
    let () = path.push(b'\0');

    let rc = unsafe { libc::stat(path.as_ptr().cast::<libc::c_char>(), dst.as_mut_ptr()) };
    if rc < 0 {
        return Err(Error::last_os_error())
    }

    // SAFETY: The object is initialized on success of `stat`.
    Ok(unsafe { dst.assume_init() })
}

/// Attempt to infer a usable non-root UID on the system.
pub fn non_root_uid() -> uid_t {
    let exe = current_exe().expect("failed to retrieve executable path");
    let stat = stat(&exe).unwrap_or_else(|err| panic!("failed to stat `{exe:?}`: {err}"));
    stat.st_uid
}

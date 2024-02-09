use std::io::Error;
use std::panic::catch_unwind;
use std::panic::UnwindSafe;

use libc::seteuid;
use libc::uid_t;


pub const NOBODY: uid_t = 65534;


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

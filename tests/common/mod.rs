#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::env::current_exe;
use std::io::Error;
use std::panic::catch_unwind;
use std::panic::UnwindSafe;

use blazesym::__private::stat;

use libc::uid_t;


/// Run a function with a different effective user ID.
#[cfg(not(windows))]
pub fn as_user<F, R>(ruid: uid_t, euid: uid_t, f: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    use libc::seteuid;

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

#[cfg(windows)]
pub fn as_user<F, R>(ruid: uid_t, euid: uid_t, f: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    unimplemented!()
}

/// Attempt to infer a usable non-root UID on the system.
pub fn non_root_uid() -> uid_t {
    let exe = current_exe().expect("failed to retrieve executable path");
    let stat = stat(&exe).unwrap_or_else(|err| panic!("failed to stat `{exe:?}`: {err}"));
    stat.st_uid
}

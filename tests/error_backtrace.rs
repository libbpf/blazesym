//! This test relies on environment variable modification for its
//! workings and, hence, relies on being run in a dedicated process. Do
//! not add additional test cases unless they are guaranteed to not
//! interfere.

#![allow(clippy::let_and_return, clippy::let_unit_value)]

use std::env;
use std::io;

use blazesym::Error;


/// Make sure that we can capture backtraces in errors.
///
/// # Notes
/// This test requires sufficient debug information to be present so
/// that the file name is contained in the backtrace. For that reason we
/// only run it on debug builds (represented by the `debug_assertions`
/// proxy cfg).
#[test]
fn error_backtrace() {
    if !cfg!(debug_assertions) {
        return
    }

    // Ensure that we capture a backtrace.
    let () = env::set_var("RUST_LIB_BACKTRACE", "1");

    let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
    let err = Error::from(err);
    let debug = format!("{err:?}");

    let start_idx = debug.find("Stack backtrace").unwrap();
    let backtrace = &debug[start_idx..];
    assert!(
        backtrace.contains("tests/error_backtrace.rs"),
        "{backtrace}"
    );
}

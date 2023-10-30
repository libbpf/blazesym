//! This test relies on environment variable modification for its
//! workings and, hence, relies on being run in a dedicated process. Do
//! not add additional test cases unless they are guaranteed to not
//! interfere.

#![allow(clippy::let_and_return, clippy::let_unit_value)]

use std::env;
use std::io;

use blazesym::Error;


/// Make sure that we do not emit backtraces in errors when
/// the `RUST_LIB_BACKTRACE` environment variable is "0".
#[test]
fn error_no_backtrace2() {
    let () = env::set_var("RUST_LIB_BACKTRACE", "0");

    let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
    let err = Error::from(err);
    let debug = format!("{err:?}");

    assert_eq!(debug.find("Stack backtrace"), None);
}

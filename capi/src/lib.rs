//! C API bindings for [`blazesym`]. Please refer to its documentation
//! for a high level overview of the functionality provided.
//!
//! # Error handling
//! Fallible functions generally return a `NULL` pointer. To provide
//! users with a better idea of what went wrong, they additionally set a
//! thread local last [error code][blaze_err]. This error indicates what
//! kind of issue caused the operation to fail.
//! A call to a fallible function always overwrites this error code. As
//! such, please make sure to check the error before making an
//! additional API call into the library.
//!
//! # Thread-Safety
//! The library does not perform any synchronization of concurrent
//! accesses to the same object. However, state is strictly kept at the
//! object level (no shared global state), meaning that while concurrent
//! accesses to the *same* object (e.g., multiple
//! [`blaze_symbolize_process_abs_addrs`] calls on the same
//! [`blaze_symbolizer`] instance) from multiple threads necessitates
//! serialization at the call site, it is fine to issue requests to
//! different objects from multiple threads.
//!
//! # Compatibility
//! The library aims to provide forward compatibility with newer
//! versions and backward compatibility with older ones. To make that
//! happen, relevant types that are being passed to the library contain
//! the `type_size` member that is to be set to the type's size, e.g.:
//! ```c
#![doc = include_str!("../examples/input-struct-init.c")]
//! ```

#![allow(
    clippy::collapsible_if,
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::manual_non_exhaustive
)]
#![deny(unsafe_op_in_unsafe_fn)]


macro_rules! input_zeroed {
    ($container_ptr:ident, $container_ty:ty) => {{
        // Each input type's first member is a `usize`.
        let user_size = unsafe { $container_ptr.cast::<usize>().read() };
        if user_size < std::mem::size_of_val(&user_size) {
            false
        } else {
            let effective_size = memoffset::offset_of!($container_ty, reserved);
            unsafe {
                crate::util::is_mem_zero(
                    $container_ptr.cast::<u8>().add(effective_size),
                    user_size.saturating_sub(effective_size),
                )
            }
        }
    }};
}


macro_rules! input_sanitize {
    ($container_ptr:ident, $container_ty:ty) => {
        unsafe {
            let user_type_size = (*$container_ptr).type_size;
            if (user_type_size < std::mem::size_of::<$container_ty>()) {
                let mut obj = std::mem::MaybeUninit::<$container_ty>::uninit();
                let buf = obj.as_mut_ptr().cast::<u8>();
                // Copy user data over local copy.
                let () =
                    std::ptr::copy_nonoverlapping($container_ptr.cast::<u8>(), buf, user_type_size);

                let () = std::ptr::write_bytes(
                    buf.add(user_type_size),
                    0,
                    std::mem::size_of::<$container_ty>() - user_type_size,
                );
                obj.assume_init()
            } else {
                $container_ptr.read()
            }
        }
    };
}


mod helper;
#[allow(non_camel_case_types)]
mod inspect;
#[allow(non_camel_case_types)]
mod normalize;
#[allow(non_camel_case_types)]
mod symbolize;
mod util;

use std::cell::Cell;
use std::ffi::c_char;

use blazesym::ErrorKind;

pub use helper::*;
pub use inspect::*;
pub use normalize::*;
pub use symbolize::*;


/// An enum providing a rough classification of errors.
///
/// C ABI compatible version of [`blazesym::ErrorKind`].
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum blaze_err {
    /// The operation was successful.
    BLAZE_ERR_OK = 0,
    /// An entity was not found, often a file.
    BLAZE_ERR_NOT_FOUND = -2,
    /// The operation lacked the necessary privileges to complete.
    BLAZE_ERR_PERMISSION_DENIED = -1,
    /// An entity already exists, often a file.
    BLAZE_ERR_ALREADY_EXISTS = -17,
    /// The operation needs to block to complete, but the blocking
    /// operation was requested to not occur.
    BLAZE_ERR_WOULD_BLOCK = -11,
    /// Data not valid for the operation were encountered.
    BLAZE_ERR_INVALID_DATA = -22,
    /// The I/O operation's timeout expired, causing it to be canceled.
    BLAZE_ERR_TIMED_OUT = -110,
    /// This operation is unsupported on this platform.
    BLAZE_ERR_UNSUPPORTED = -95,
    /// An operation could not be completed, because it failed
    /// to allocate enough memory.
    BLAZE_ERR_OUT_OF_MEMORY = -12,
    /// A parameter was incorrect.
    BLAZE_ERR_INVALID_INPUT = -256,
    /// An error returned when an operation could not be completed
    /// because a call to [`write`] returned [`Ok(0)`].
    BLAZE_ERR_WRITE_ZERO = -257,
    /// An error returned when an operation could not be completed
    /// because an "end of file" was reached prematurely.
    BLAZE_ERR_UNEXPECTED_EOF = -258,
    /// DWARF input data was invalid.
    BLAZE_ERR_INVALID_DWARF = -259,
    /// A custom error that does not fall under any other I/O error
    /// kind.
    BLAZE_ERR_OTHER = -260,
}

impl From<ErrorKind> for blaze_err {
    fn from(other: ErrorKind) -> Self {
        match other {
            ErrorKind::NotFound => blaze_err::BLAZE_ERR_NOT_FOUND,
            ErrorKind::PermissionDenied => blaze_err::BLAZE_ERR_PERMISSION_DENIED,
            ErrorKind::AlreadyExists => blaze_err::BLAZE_ERR_ALREADY_EXISTS,
            ErrorKind::WouldBlock => blaze_err::BLAZE_ERR_WOULD_BLOCK,
            ErrorKind::InvalidInput => blaze_err::BLAZE_ERR_INVALID_INPUT,
            ErrorKind::InvalidData => blaze_err::BLAZE_ERR_INVALID_DATA,
            ErrorKind::InvalidDwarf => blaze_err::BLAZE_ERR_INVALID_DWARF,
            ErrorKind::TimedOut => blaze_err::BLAZE_ERR_TIMED_OUT,
            ErrorKind::WriteZero => blaze_err::BLAZE_ERR_WRITE_ZERO,
            ErrorKind::Unsupported => blaze_err::BLAZE_ERR_UNSUPPORTED,
            ErrorKind::UnexpectedEof => blaze_err::BLAZE_ERR_UNEXPECTED_EOF,
            ErrorKind::OutOfMemory => blaze_err::BLAZE_ERR_OUT_OF_MEMORY,
            ErrorKind::Other => blaze_err::BLAZE_ERR_OTHER,
            _ => unreachable!(),
        }
    }
}


thread_local! {
    /// The error reported by the last fallible API function invoked.
    static LAST_ERR: Cell<blaze_err> = const { Cell::new(blaze_err::BLAZE_ERR_OK) };
}

/// Retrieve the error reported by the last fallible API function invoked.
#[no_mangle]
pub extern "C" fn blaze_err_last() -> blaze_err {
    LAST_ERR.with(|cell| cell.get())
}

/// Retrieve the error reported by the last fallible API function invoked.
fn set_last_err(err: blaze_err) {
    LAST_ERR.with(|cell| cell.set(err))
}


/// Retrieve a textual representation of the error code.
#[no_mangle]
pub extern "C" fn blaze_err_str(err: blaze_err) -> *const c_char {
    match err as i32 {
        e if e == blaze_err::BLAZE_ERR_OK as i32 => b"success\0".as_ptr().cast(),
        e if e == blaze_err::BLAZE_ERR_NOT_FOUND as i32 => {
            ErrorKind::NotFound.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_PERMISSION_DENIED as i32 => {
            ErrorKind::PermissionDenied.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_ALREADY_EXISTS as i32 => {
            ErrorKind::AlreadyExists.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_WOULD_BLOCK as i32 => {
            ErrorKind::WouldBlock.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_INVALID_INPUT as i32 => {
            ErrorKind::InvalidInput.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_INVALID_DATA as i32 => {
            ErrorKind::InvalidData.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_INVALID_DWARF as i32 => {
            ErrorKind::InvalidDwarf.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_TIMED_OUT as i32 => {
            ErrorKind::TimedOut.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_WRITE_ZERO as i32 => {
            ErrorKind::WriteZero.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_UNSUPPORTED as i32 => {
            ErrorKind::Unsupported.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_UNEXPECTED_EOF as i32 => {
            ErrorKind::UnexpectedEof.as_bytes().as_ptr().cast()
        }
        e if e == blaze_err::BLAZE_ERR_OUT_OF_MEMORY as i32 => {
            ErrorKind::OutOfMemory.as_bytes().as_ptr().cast()
        }
        _ => ErrorKind::Other.as_bytes().as_ptr().cast(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CStr;


    /// Check that we can convert `ErrorKind` instances into `blaze_err`.
    #[test]
    fn error_conversion() {
        let data = [
            (ErrorKind::NotFound, blaze_err::BLAZE_ERR_NOT_FOUND),
            (
                ErrorKind::PermissionDenied,
                blaze_err::BLAZE_ERR_PERMISSION_DENIED,
            ),
            (
                ErrorKind::AlreadyExists,
                blaze_err::BLAZE_ERR_ALREADY_EXISTS,
            ),
            (ErrorKind::WouldBlock, blaze_err::BLAZE_ERR_WOULD_BLOCK),
            (ErrorKind::InvalidInput, blaze_err::BLAZE_ERR_INVALID_INPUT),
            (ErrorKind::InvalidData, blaze_err::BLAZE_ERR_INVALID_DATA),
            (ErrorKind::InvalidDwarf, blaze_err::BLAZE_ERR_INVALID_DWARF),
            (ErrorKind::TimedOut, blaze_err::BLAZE_ERR_TIMED_OUT),
            (ErrorKind::WriteZero, blaze_err::BLAZE_ERR_WRITE_ZERO),
            (ErrorKind::Unsupported, blaze_err::BLAZE_ERR_UNSUPPORTED),
            (
                ErrorKind::UnexpectedEof,
                blaze_err::BLAZE_ERR_UNEXPECTED_EOF,
            ),
            (ErrorKind::OutOfMemory, blaze_err::BLAZE_ERR_OUT_OF_MEMORY),
            (ErrorKind::Other, blaze_err::BLAZE_ERR_OTHER),
        ];

        for (kind, expected) in data {
            assert_eq!(blaze_err::from(kind), expected);
            let cstr = unsafe { CStr::from_ptr(blaze_err_str(expected)) };
            let expected = CStr::from_bytes_with_nul(kind.as_bytes()).unwrap();
            assert_eq!(cstr, expected);
        }
    }
}

use std::cell::Cell;
use std::ffi::c_char;

use blazesym::ErrorKind;


/// An enum providing a rough classification of errors.
///
/// C ABI compatible version of [`blazesym::ErrorKind`].
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
pub(crate) fn set_last_err(err: blaze_err) {
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

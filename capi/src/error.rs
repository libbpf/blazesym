use std::cell::Cell;
use std::ffi::c_char;

use blazesym::ErrorKind;


/// An enum providing a rough classification of errors.
///
/// C ABI compatible version of [`blazesym::ErrorKind`].
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct blaze_err(i16);

impl blaze_err {
    /// The operation was successful.
    pub const OK: Self = Self(0);
    /// An entity was not found, often a file.
    pub const NOT_FOUND: Self = Self(-2);
    /// The operation lacked the necessary privileges to complete.
    pub const PERMISSION_DENIED: Self = Self(-1);
    /// An entity already exists, often a file.
    pub const ALREADY_EXISTS: Self = Self(-17);
    /// The operation needs to block to complete, but the blocking
    /// operation was requested to not occur.
    pub const WOULD_BLOCK: Self = Self(-11);
    /// Data not valid for the operation were encountered.
    pub const INVALID_DATA: Self = Self(-22);
    /// The I/O operation's timeout expired, causing it to be canceled.
    pub const TIMED_OUT: Self = Self(-110);
    /// This operation is unsupported on this platform.
    pub const UNSUPPORTED: Self = Self(-95);
    /// An operation could not be completed, because it failed
    /// to allocate enough memory.
    pub const OUT_OF_MEMORY: Self = Self(-12);
    /// A parameter was incorrect.
    pub const INVALID_INPUT: Self = Self(-256);
    /// An error returned when an operation could not be completed
    /// because a call to [`write`][std::io::Write::write] returned
    /// [`Ok(0)`][Ok].
    pub const WRITE_ZERO: Self = Self(-257);
    /// An error returned when an operation could not be completed
    /// because an "end of file" was reached prematurely.
    pub const UNEXPECTED_EOF: Self = Self(-258);
    /// DWARF input data was invalid.
    pub const INVALID_DWARF: Self = Self(-259);
    /// A custom error that does not fall under any other I/O error
    /// kind.
    pub const OTHER: Self = Self(-260);
}

impl From<ErrorKind> for blaze_err {
    fn from(other: ErrorKind) -> Self {
        match other {
            ErrorKind::NotFound => Self::NOT_FOUND,
            ErrorKind::PermissionDenied => Self::PERMISSION_DENIED,
            ErrorKind::AlreadyExists => Self::ALREADY_EXISTS,
            ErrorKind::WouldBlock => Self::WOULD_BLOCK,
            ErrorKind::InvalidInput => Self::INVALID_INPUT,
            ErrorKind::InvalidData => Self::INVALID_DATA,
            ErrorKind::InvalidDwarf => Self::INVALID_DWARF,
            ErrorKind::TimedOut => Self::TIMED_OUT,
            ErrorKind::WriteZero => Self::WRITE_ZERO,
            ErrorKind::Unsupported => Self::UNSUPPORTED,
            ErrorKind::UnexpectedEof => Self::UNEXPECTED_EOF,
            ErrorKind::OutOfMemory => Self::OUT_OF_MEMORY,
            ErrorKind::Other => Self::OTHER,
            _ => unreachable!(),
        }
    }
}


thread_local! {
    /// The error reported by the last fallible API function invoked.
    static LAST_ERR: Cell<blaze_err> = const { Cell::new(blaze_err::OK) };
}

/// Retrieve the error reported by the last fallible API function invoked.
#[no_mangle]
pub extern "C" fn blaze_err_last() -> blaze_err {
    LAST_ERR.with(Cell::get)
}

/// Retrieve the error reported by the last fallible API function invoked.
pub(crate) fn set_last_err(err: blaze_err) {
    LAST_ERR.with(|cell| cell.set(err))
}


/// Retrieve a textual representation of the error code.
#[no_mangle]
pub extern "C" fn blaze_err_str(err: blaze_err) -> *const c_char {
    match err {
        blaze_err::OK => b"success\0".as_ptr().cast(),
        blaze_err::NOT_FOUND => ErrorKind::NotFound.as_bytes().as_ptr().cast(),
        blaze_err::PERMISSION_DENIED => ErrorKind::PermissionDenied.as_bytes().as_ptr().cast(),
        blaze_err::ALREADY_EXISTS => ErrorKind::AlreadyExists.as_bytes().as_ptr().cast(),
        blaze_err::WOULD_BLOCK => ErrorKind::WouldBlock.as_bytes().as_ptr().cast(),
        blaze_err::INVALID_INPUT => ErrorKind::InvalidInput.as_bytes().as_ptr().cast(),
        blaze_err::INVALID_DATA => ErrorKind::InvalidData.as_bytes().as_ptr().cast(),
        blaze_err::INVALID_DWARF => ErrorKind::InvalidDwarf.as_bytes().as_ptr().cast(),
        blaze_err::TIMED_OUT => ErrorKind::TimedOut.as_bytes().as_ptr().cast(),
        blaze_err::WRITE_ZERO => ErrorKind::WriteZero.as_bytes().as_ptr().cast(),
        blaze_err::UNSUPPORTED => ErrorKind::Unsupported.as_bytes().as_ptr().cast(),
        blaze_err::UNEXPECTED_EOF => ErrorKind::UnexpectedEof.as_bytes().as_ptr().cast(),
        blaze_err::OUT_OF_MEMORY => ErrorKind::OutOfMemory.as_bytes().as_ptr().cast(),
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
            (ErrorKind::NotFound, blaze_err::NOT_FOUND),
            (ErrorKind::PermissionDenied, blaze_err::PERMISSION_DENIED),
            (ErrorKind::AlreadyExists, blaze_err::ALREADY_EXISTS),
            (ErrorKind::WouldBlock, blaze_err::WOULD_BLOCK),
            (ErrorKind::InvalidInput, blaze_err::INVALID_INPUT),
            (ErrorKind::InvalidData, blaze_err::INVALID_DATA),
            (ErrorKind::InvalidDwarf, blaze_err::INVALID_DWARF),
            (ErrorKind::TimedOut, blaze_err::TIMED_OUT),
            (ErrorKind::WriteZero, blaze_err::WRITE_ZERO),
            (ErrorKind::Unsupported, blaze_err::UNSUPPORTED),
            (ErrorKind::UnexpectedEof, blaze_err::UNEXPECTED_EOF),
            (ErrorKind::OutOfMemory, blaze_err::OUT_OF_MEMORY),
            (ErrorKind::Other, blaze_err::OTHER),
        ];

        for (kind, expected) in data {
            assert_eq!(blaze_err::from(kind), expected);
            let cstr = unsafe { CStr::from_ptr(blaze_err_str(expected)) };
            let expected = CStr::from_bytes_with_nul(kind.as_bytes()).unwrap();
            assert_eq!(cstr, expected);
        }
    }
}

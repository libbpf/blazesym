use std::backtrace::Backtrace;
use std::backtrace::BacktraceStatus;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::mem::transmute;
use std::ops::Deref;
use std::str;


mod private {
    use super::io;
    use super::str;
    use super::Error;

    pub trait Sealed {}

    impl<T> Sealed for Option<T> {}
    impl<T, E> Sealed for Result<T, E> {}
    impl Sealed for &'static str {}
    impl Sealed for String {}
    impl Sealed for Error {}

    impl Sealed for io::Error {}
    #[cfg(feature = "breakpad")]
    #[allow(clippy::absolute_paths)]
    impl Sealed for (&[u8], nom::Err<nom::error::VerboseError<&[u8]>>) {}
    #[cfg(feature = "dwarf")]
    impl Sealed for gimli::Error {}
}

/// A `str` replacement whose owned representation is a `Box<str>` and
/// not a `String`.
#[derive(Debug)]
#[repr(transparent)]
#[doc(hidden)]
pub struct Str(str);

impl ToOwned for Str {
    type Owned = Box<str>;

    #[inline]
    fn to_owned(&self) -> Self::Owned {
        self.0.to_string().into_boxed_str()
    }
}

impl Borrow<Str> for Box<str> {
    #[inline]
    fn borrow(&self) -> &Str {
        // SAFETY: `Str` is `repr(transparent)` and so `&str` and `&Str`
        //         can trivially be converted into each other.
        unsafe { transmute::<&str, &Str>(self.deref()) }
    }
}

impl Deref for Str {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// For convenient use in `format!`, for example.
impl Display for Str {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}


/// A helper trait to abstracting over various string types, allowing
/// for conversion into a `Cow<'static, Str>`. This is the `Cow` enabled
/// equivalent of `ToString`.
pub trait IntoCowStr: private::Sealed {
    fn into_cow_str(self) -> Cow<'static, Str>;
}

impl IntoCowStr for &'static str {
    fn into_cow_str(self) -> Cow<'static, Str> {
        // SAFETY: `Str` is `repr(transparent)` and so `&str` and `&Str`
        //         can trivially be converted into each other.
        let other = unsafe { transmute::<&str, &Str>(self) };
        Cow::Borrowed(other)
    }
}

impl IntoCowStr for String {
    fn into_cow_str(self) -> Cow<'static, Str> {
        Cow::Owned(self.into_boxed_str())
    }
}


enum ErrorImpl {
    #[cfg(feature = "dwarf")]
    Dwarf {
        error: gimli::Error,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    Io {
        error: io::Error,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    Std {
        error: Box<dyn StdError + Send + Sync + 'static>,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    // Unfortunately, if we just had a single `Context` variant that
    // contains a `Cow`, this inner `Cow` would cause an overall enum
    // size increase by a machine word, because currently `rustc`
    // seemingly does not fold the necessary bits into the outer enum.
    // We have two variants to work around that until `rustc` is smart
    // enough.
    ContextOwned {
        context: Box<str>,
        source: Box<ErrorImpl>,
    },
    ContextStatic {
        context: &'static str,
        source: Box<ErrorImpl>,
    },
}

impl ErrorImpl {
    fn kind(&self) -> ErrorKind {
        match self {
            #[cfg(feature = "dwarf")]
            Self::Dwarf { .. } => ErrorKind::InvalidDwarf,
            Self::Io { error, .. } => match error.kind() {
                io::ErrorKind::NotFound => ErrorKind::NotFound,
                io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
                io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
                io::ErrorKind::WouldBlock => ErrorKind::WouldBlock,
                io::ErrorKind::InvalidInput => ErrorKind::InvalidInput,
                io::ErrorKind::InvalidData => ErrorKind::InvalidData,
                io::ErrorKind::TimedOut => ErrorKind::TimedOut,
                io::ErrorKind::WriteZero => ErrorKind::WriteZero,
                io::ErrorKind::Unsupported => ErrorKind::Unsupported,
                io::ErrorKind::UnexpectedEof => ErrorKind::UnexpectedEof,
                io::ErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
                _ => ErrorKind::Other,
            },
            Self::Std { .. } => ErrorKind::Other,
            Self::ContextOwned { source, .. } | Self::ContextStatic { source, .. } => {
                source.deref().kind()
            }
        }
    }

    /// Retrieve the object's associated backtrace, if any.
    #[cfg(feature = "backtrace")]
    fn backtrace(&self) -> Option<&Backtrace> {
        match self {
            #[cfg(feature = "dwarf")]
            Self::Dwarf { backtrace, .. } => Some(backtrace),
            Self::Io { backtrace, .. } => Some(backtrace),
            Self::Std { backtrace, .. } => Some(backtrace),
            Self::ContextOwned { .. } => None,
            Self::ContextStatic { .. } => None,
        }
    }

    /// Stub for retrieving no backtrace, as support is compiled out.
    #[cfg(not(feature = "backtrace"))]
    fn backtrace(&self) -> Option<&Backtrace> {
        None
    }

    #[cfg(test)]
    fn is_owned(&self) -> Option<bool> {
        match self {
            Self::ContextOwned { .. } => Some(true),
            Self::ContextStatic { .. } => Some(false),
            _ => None,
        }
    }
}

impl Debug for ErrorImpl {
    // We try to mirror roughly how anyhow's Error is behaving, because
    // that makes the most sense.
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if f.alternate() {
            let mut dbg;

            match self {
                #[cfg(feature = "dwarf")]
                Self::Dwarf { error, .. } => {
                    dbg = f.debug_tuple(stringify!(Dwarf));
                    dbg.field(error)
                }
                Self::Io { error, .. } => {
                    dbg = f.debug_tuple(stringify!(Io));
                    dbg.field(error)
                }
                Self::Std { error, .. } => {
                    dbg = f.debug_tuple(stringify!(Std));
                    dbg.field(error)
                }
                Self::ContextOwned { context, .. } => {
                    dbg = f.debug_tuple(stringify!(ContextOwned));
                    dbg.field(context)
                }
                Self::ContextStatic { context, .. } => {
                    dbg = f.debug_tuple(stringify!(ContextStatic));
                    dbg.field(context)
                }
            }
            .finish()
        } else {
            let () = match self {
                #[cfg(feature = "dwarf")]
                Self::Dwarf { error, .. } => write!(f, "Error: {error}")?,
                Self::Io { error, .. } => write!(f, "Error: {error}")?,
                Self::Std { error, .. } => write!(f, "Error: {error}")?,
                Self::ContextOwned { context, .. } => write!(f, "Error: {context}")?,
                Self::ContextStatic { context, .. } => write!(f, "Error: {context}")?,
            };

            if let Some(source) = self.source() {
                let () = f.write_str("\n\nCaused by:")?;

                let mut error = Some(source);
                while let Some(err) = error {
                    let () = write!(f, "\n    {err:}")?;
                    error = err.source();
                }
            }

            match self.backtrace() {
                Some(backtrace) if backtrace.status() == BacktraceStatus::Captured => {
                    let () = write!(f, "\n\nStack backtrace:\n{backtrace}")?;
                }
                _ => (),
            }
            Ok(())
        }
    }
}

impl Display for ErrorImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let () = match self {
            #[cfg(feature = "dwarf")]
            Self::Dwarf { error, .. } => Display::fmt(error, f)?,
            Self::Io { error, .. } => Display::fmt(error, f)?,
            Self::Std { error, .. } => Display::fmt(error, f)?,
            Self::ContextOwned { context, .. } => Display::fmt(context, f)?,
            Self::ContextStatic { context, .. } => Display::fmt(context, f)?,
        };

        if f.alternate() {
            let mut error = self.source();
            while let Some(err) = error {
                let () = write!(f, ": {err}")?;
                error = err.source();
            }
        }
        Ok(())
    }
}

impl StdError for ErrorImpl {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            #[cfg(feature = "dwarf")]
            Self::Dwarf { error, .. } => error.source(),
            Self::Io { error, .. } => error.source(),
            Self::Std { error, .. } => error.source(),
            Self::ContextOwned { source, .. } | Self::ContextStatic { source, .. } => Some(source),
        }
    }
}


/// An enum providing a rough classification of errors.
///
/// The variants of this type partly resemble those of
/// [`std::io::Error`], because these are the most common sources of
/// error that the crate concerns itself with. On top of that, however,
/// there are additional more specific variants such as
/// [`InvalidDwarf`][ErrorKind::InvalidDwarf].
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An entity was not found, often a file.
    NotFound,
    /// The operation lacked the necessary privileges to complete.
    PermissionDenied,
    /// An entity already exists, often a file.
    AlreadyExists,
    /// The operation needs to block to complete, but the blocking
    /// operation was requested to not occur.
    WouldBlock,
    /// A parameter was incorrect.
    InvalidInput,
    /// Data not valid for the operation were encountered.
    InvalidData,
    /// DWARF input data was invalid.
    InvalidDwarf,
    /// The I/O operation's timeout expired, causing it to be canceled.
    TimedOut,
    /// An error returned when an operation could not be completed
    /// because a call to [`write`] returned [`Ok(0)`].
    WriteZero,
    /// This operation is unsupported on this platform.
    Unsupported,
    /// An error returned when an operation could not be completed
    /// because an "end of file" was reached prematurely.
    UnexpectedEof,
    /// An operation could not be completed, because it failed
    /// to allocate enough memory.
    OutOfMemory,
    /// A custom error that does not fall under any other I/O error
    /// kind.
    Other,
}

impl ErrorKind {
    #[doc(hidden)]
    #[inline]
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::AlreadyExists => b"entity already exists\0",
            Self::InvalidData => b"invalid data\0",
            Self::InvalidInput => b"invalid input parameter\0",
            Self::NotFound => b"entity not found\0",
            Self::Other => b"other error\0",
            Self::OutOfMemory => b"out of memory\0",
            Self::PermissionDenied => b"permission denied\0",
            Self::TimedOut => b"timed out\0",
            Self::UnexpectedEof => b"unexpected end of file\0",
            Self::Unsupported => b"unsupported\0",
            Self::WouldBlock => b"operation would block\0",
            Self::WriteZero => b"write zero\0",
            Self::InvalidDwarf => b"DWARF data invalid\0",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let cstr = self.as_bytes();
        // SAFETY: `as_bytes` always returns a valid string.
        let s = unsafe { str::from_utf8_unchecked(&cstr[..cstr.len() - 1]) };
        f.write_str(s)
    }
}


/// The error type used by the library.
///
/// Errors generally form a chain, with higher-level errors typically
/// providing additional context for lower level ones. E.g., an IO error
/// such as file-not-found could be reported by a system level API (such
/// as [`std::fs::File::open`]) and may be contextualized with the path
/// to the file attempted to be opened.
///
/// ```
/// use std::fs::File;
/// use std::error::Error as _;
/// # use blazesym::ErrorExt as _;
///
/// let path = "/does-not-exist";
/// let result = File::open(path).with_context(|| format!("failed to open {path}"));
///
/// let err = result.unwrap_err();
/// assert_eq!(err.to_string(), "failed to open /does-not-exist");
///
/// // Retrieve the underlying error.
/// let inner_err = err.source().unwrap();
/// assert!(inner_err.to_string().starts_with("No such file or directory"));
/// ```
///
/// For convenient reporting, the [`Display`] representation takes care
/// of reporting the complete error chain when the alternate flag is
/// set:
/// ```
/// # use std::fs::File;
/// # use std::error::Error as _;
/// # use blazesym::ErrorExt as _;
/// # let path = "/does-not-exist";
/// # let result = File::open(path).with_context(|| format!("failed to open {path}"));
/// # let err = result.unwrap_err();
/// // > failed to open /does-not-exist: No such file or directory (os error 2)
/// println!("{err:#}");
/// ```
///
/// The [`Debug`] representation similarly will print the entire error
/// chain, but will do so in a multi-line format:
/// ```
/// # use std::fs::File;
/// # use std::error::Error as _;
/// # use blazesym::ErrorExt as _;
/// # let path = "/does-not-exist";
/// # let result = File::open(path).with_context(|| format!("failed to open {path}"));
/// # let err = result.unwrap_err();
/// // > Error: failed to open /does-not-exist
/// // >
/// // > Caused by:
/// // >     No such file or directory (os error 2)
/// println!("{err:?}");
/// ```
///
/// On top of that, if the `backtrace` feature is enabled, errors may also
/// contain an optional backtrace. Backtrace capturing behavior follows the
/// exact rules set forth by the [`std::backtrace`] module. That is, it is
/// controlled by the `RUST_BACKTRACE` and `RUST_LIB_BACKTRACE` environment
/// variables. Please refer to this module's documentation for precise
/// semantics, but in short:
/// - If you want panics and errors to both have backtraces, set
///   `RUST_BACKTRACE=1`
/// - If you want only errors to have backtraces, set `RUST_LIB_BACKTRACE=1`
/// - If you want only panics to have backtraces, set `RUST_BACKTRACE=1` and
///   `RUST_LIB_BACKTRACE=0`
// Representation is optimized for fast copying (a single machine word),
// not so much for fast creation (as it is heap allocated). We generally
// expect errors to be exceptional, though a lot of functionality is
// fallible (i.e., returns a `Result<T, Error>` which would be penalized
// by a large `Err` variant).
#[repr(transparent)]
pub struct Error {
    /// The top-most error of the chain.
    error: Box<ErrorImpl>,
}

impl Error {
    #[cold]
    fn with_io_error<E>(kind: io::ErrorKind, error: E) -> Self
    where
        E: ToString,
    {
        Self::from(io::Error::new(kind, error.to_string()))
    }

    #[inline]
    pub(crate) fn with_not_found<E>(error: E) -> Self
    where
        E: ToString,
    {
        Self::with_io_error(io::ErrorKind::NotFound, error)
    }

    #[inline]
    pub(crate) fn with_invalid_data<E>(error: E) -> Self
    where
        E: ToString,
    {
        Self::with_io_error(io::ErrorKind::InvalidData, error)
    }

    #[inline]
    pub(crate) fn with_invalid_input<E>(error: E) -> Self
    where
        E: ToString,
    {
        Self::with_io_error(io::ErrorKind::InvalidInput, error)
    }

    #[inline]
    pub(crate) fn with_unsupported<E>(error: E) -> Self
    where
        E: ToString,
    {
        Self::with_io_error(io::ErrorKind::Unsupported, error)
    }

    /// Retrieve a rough error classification in the form of an
    /// [`ErrorKind`].
    #[inline]
    pub fn kind(&self) -> ErrorKind {
        self.error.kind()
    }

    /// Layer the provided context on top of this `Error`, creating a
    /// new one in the process.
    #[cold]
    fn layer_context(self, context: Cow<'static, Str>) -> Self {
        match context {
            Cow::Owned(context) => Self {
                error: Box::new(ErrorImpl::ContextOwned {
                    context,
                    source: self.error,
                }),
            },
            Cow::Borrowed(context) => Self {
                error: Box::new(ErrorImpl::ContextStatic {
                    context,
                    source: self.error,
                }),
            },
        }
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self.error, f)
    }
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.error, f)
    }
}

impl StdError for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.source()
    }
}

#[cfg(feature = "dwarf")]
impl From<gimli::Error> for Error {
    fn from(other: gimli::Error) -> Self {
        Self {
            error: Box::new(ErrorImpl::Dwarf {
                error: other,
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture(),
            }),
        }
    }
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self {
        Self {
            error: Box::new(ErrorImpl::Io {
                error: other,
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture(),
            }),
        }
    }
}

impl From<Box<dyn StdError + Send + Sync + 'static>> for Error {
    fn from(other: Box<dyn StdError + Send + Sync + 'static>) -> Self {
        Self {
            error: Box::new(ErrorImpl::Std {
                error: other,
                // Ideally we'd use any backtrace potentially attached to the
                // error, but we have no way of knowing that or accessing it,
                // because no trait exposes it. So the best we can do is capture
                // a backtrace ourselves. Sigh.
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture(),
            }),
        }
    }
}


/// A trait providing ergonomic chaining capabilities to [`Error`].
pub trait ErrorExt: private::Sealed {
    /// The output type produced by [`context`](Self::context) and
    /// [`with_context`](Self::with_context).
    type Output;

    /// Add context to this error.
    // If we had specialization of sorts we could be more lenient as to
    // what we can accept, but for now this method always works with
    // static strings and nothing else.
    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr;

    /// Add context to this error, using a closure for lazy evaluation.
    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C;
}

impl ErrorExt for Error {
    type Output = Error;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr,
    {
        self.layer_context(context.into_cow_str())
    }

    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C,
    {
        self.layer_context(f().into_cow_str())
    }
}

impl<T, E> ErrorExt for Result<T, E>
where
    E: ErrorExt,
{
    type Output = Result<T, E::Output>;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr,
    {
        match self {
            Ok(val) => Ok(val),
            Err(err) => Err(err.context(context)),
        }
    }

    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C,
    {
        match self {
            Ok(val) => Ok(val),
            Err(err) => Err(err.with_context(f)),
        }
    }
}

impl ErrorExt for io::Error {
    type Output = Error;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr,
    {
        Error::from(self).context(context)
    }

    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C,
    {
        Error::from(self).with_context(f)
    }
}


/// A trait providing conversion shortcuts for creating [`Error`]
/// instances.
pub trait IntoError<T>: private::Sealed
where
    Self: Sized,
{
    /// Unwrap `self` into an `Ok` or an [`Error`] of the given kind.
    fn ok_or_error<C, F>(self, kind: io::ErrorKind, f: F) -> Result<T, Error>
    where
        C: ToString,
        F: FnOnce() -> C;

    /// Unwrap `self` into an `Ok` or an [`Error`] of the
    /// [`ErrorKind::InvalidData`] kind.
    #[inline]
    fn ok_or_invalid_data<C, F>(self, f: F) -> Result<T, Error>
    where
        C: ToString,
        F: FnOnce() -> C,
    {
        self.ok_or_error(io::ErrorKind::InvalidData, f)
    }

    /// Unwrap `self` into an `Ok` or an [`Error`] of the
    /// [`ErrorKind::InvalidInput`] kind.
    #[inline]
    fn ok_or_invalid_input<C, F>(self, f: F) -> Result<T, Error>
    where
        C: ToString,
        F: FnOnce() -> C,
    {
        self.ok_or_error(io::ErrorKind::InvalidInput, f)
    }

    /// Unwrap `self` into an `Ok` or an [`Error`] of the
    /// [`ErrorKind::NotFound`] kind.
    #[inline]
    fn ok_or_not_found<C, F>(self, f: F) -> Result<T, Error>
    where
        C: ToString,
        F: FnOnce() -> C,
    {
        self.ok_or_error(io::ErrorKind::NotFound, f)
    }

    /// Unwrap `self` into an `Ok` or an [`Error`] of the
    /// [`ErrorKind::UnexpectedEof`] kind.
    #[inline]
    fn ok_or_unexpected_eof<C, F>(self, f: F) -> Result<T, Error>
    where
        C: ToString,
        F: FnOnce() -> C,
    {
        self.ok_or_error(io::ErrorKind::UnexpectedEof, f)
    }
}

impl<T> IntoError<T> for Option<T> {
    #[inline]
    fn ok_or_error<C, F>(self, kind: io::ErrorKind, f: F) -> Result<T, Error>
    where
        C: ToString,
        F: FnOnce() -> C,
    {
        self.ok_or_else(|| Error::with_io_error(kind, f()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::mem::size_of;

    use test_fork::fork;
    use test_log::test;
    use test_tag::tag;


    /// Exercise the `Display` representation of various types.
    #[tag(miri)]
    #[test]
    fn display_repr() {
        assert_eq!(ErrorKind::NotFound.to_string(), "entity not found");
        assert_eq!(ErrorKind::OutOfMemory.to_string(), "out of memory");
        assert_eq!(
            ErrorKind::UnexpectedEof.to_string(),
            "unexpected end of file"
        );
    }

    /// Check various features of our `Str` wrapper type.
    #[tag(miri)]
    #[test]
    fn str_wrapper() {
        let b = "test string".to_string().into_boxed_str();
        let s: &Str = b.borrow();
        let _b: Box<str> = s.to_owned();

        assert_eq!(s.to_string(), b.deref());
        assert_eq!(format!("{s:?}"), "Str(\"test string\")");
    }

    /// Check that our `Error` type's size is as expected.
    #[test]
    fn error_size() {
        assert_eq!(size_of::<Error>(), size_of::<usize>());
    }

    /// Check that we can convert a `dyn std::error::Error` into our `Error`.
    #[tag(miri)]
    #[test]
    fn std_error_conversion() {
        let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
        let err = Box::new(err) as Box<dyn StdError + Send + Sync + 'static>;
        let err = Error::from(err);

        assert_eq!(format!("{err}"), "some invalid data");
        // The original error kind won't be preserved, unfortunately.
        assert_eq!(err.kind(), ErrorKind::Other);
    }

    /// Check `Error::kind` reports the expected value.
    #[tag(miri)]
    #[test]
    fn error_kind() {
        let err = Error::from(io::Error::new(io::ErrorKind::AlreadyExists, "oops"));
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);

        let err = Error::from(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        let err = Error::from(io::Error::new(io::ErrorKind::TimedOut, "Ba Dum Tss"));
        assert_eq!(err.kind(), ErrorKind::TimedOut);

        let err = Error::from(io::Error::new(io::ErrorKind::WriteZero, "Nothing there :/"));
        assert_eq!(err.kind(), ErrorKind::WriteZero);

        let err = Error::from(io::Error::new(io::ErrorKind::UnexpectedEof, "Ohh?"));
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

        let err = Error::from(io::Error::new(io::ErrorKind::OutOfMemory, "oom"));
        assert_eq!(err.kind(), ErrorKind::OutOfMemory);
    }

    /// Check that we can format errors as expected.
    #[tag(miri)]
    #[test]
    fn error_formatting() {
        let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
        let err = Error::from(err);

        let src = err.source();
        assert!(src.is_none(), "{src:?}");
        assert!(err.error.is_owned().is_none());
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(format!("{err}"), "some invalid data");
        assert_eq!(format!("{err:#}"), "some invalid data");
        assert!(format!("{err:?}").starts_with("Error: some invalid data"));
        // TODO: The inner format may not actually be all that stable.
        let expected = r#"Io(
    Custom {
        kind: InvalidData,
        error: "some invalid data",
    },
)"#;
        assert_eq!(format!("{err:#?}"), expected);

        let err = err.context("inner context");
        let src = err.source();
        assert!(src.is_some(), "{src:?}");
        assert!(!err.error.is_owned().unwrap());
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(format!("{err}"), "inner context");
        assert_eq!(format!("{err:#}"), "inner context: some invalid data");

        let expected = r#"Error: inner context

Caused by:
    some invalid data"#;
        assert_eq!(format!("{err:?}"), expected);
        // Nope, not going to bother.
        assert_ne!(format!("{err:#?}"), "");

        let err = err.context("outer context".to_string());
        let src = err.source();
        assert!(src.is_some(), "{src:?}");
        assert!(err.error.is_owned().unwrap());
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(format!("{err}"), "outer context");
        assert_eq!(
            format!("{err:#}"),
            "outer context: inner context: some invalid data"
        );

        let expected = r#"Error: outer context

Caused by:
    inner context
    some invalid data"#;
        assert_eq!(format!("{err:?}"), expected);
        assert_ne!(format!("{err:#?}"), "");
    }

    /// Make sure that we can capture backtraces in errors.
    ///
    /// # Notes
    /// This test requires sufficient debug information to be present so
    /// that the file name is contained in the backtrace. For that reason we
    /// only run it on debug builds (represented by the `debug_assertions`
    /// proxy cfg).
    #[fork]
    #[test]
    fn error_backtrace() {
        if !cfg!(debug_assertions) {
            return
        }

        // Ensure that we capture a backtrace.
        let () = unsafe { env::set_var("RUST_LIB_BACKTRACE", "1") };

        let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
        let err = Error::from(err);
        let debug = format!("{err:?}");

        let start_idx = debug.find("Stack backtrace").unwrap();
        let backtrace = &debug[start_idx..];
        assert!(backtrace.contains("src/error.rs"), "{backtrace}");
    }

    /// Make sure that we do not emit backtraces in errors when
    /// the `RUST_LIB_BACKTRACE` environment variable is not present.
    #[fork]
    #[test]
    fn error_no_backtrace1() {
        let () = unsafe { env::remove_var("RUST_BACKTRACE") };
        let () = unsafe { env::remove_var("RUST_LIB_BACKTRACE") };

        let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
        let err = Error::from(err);
        let debug = format!("{err:?}");

        assert_eq!(debug.find("Stack backtrace"), None);
    }

    /// Make sure that we do not emit backtraces in errors when
    /// the `RUST_LIB_BACKTRACE` environment variable is "0".
    #[fork]
    #[test]
    fn error_no_backtrace2() {
        let () = unsafe { env::remove_var("RUST_BACKTRACE") };
        let () = unsafe { env::set_var("RUST_LIB_BACKTRACE", "0") };

        let err = io::Error::new(io::ErrorKind::InvalidData, "some invalid data");
        let err = Error::from(err);
        let debug = format!("{err:?}");

        assert_eq!(debug.find("Stack backtrace"), None);
    }
}

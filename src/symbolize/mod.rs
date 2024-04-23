//! Functionality for symbolizing addresses.
//!
//! This module contains functionality for symbolizing addresses, i.e., finding
//! symbol names and other information based on "raw" addresses.
//!
//! For example, here we symbolize the address of `libc`'s `fopen` and `fseek`
//! functions, given their addresses in the current process:
//! ```no_run
//! use blazesym::symbolize::Input;
//! use blazesym::symbolize::Process;
//! use blazesym::symbolize::Source;
//! use blazesym::symbolize::Symbolizer;
//! use blazesym::Addr;
//! use blazesym::Pid;
//!
//! let addrs = [libc::fopen as Addr, libc::fseek as Addr];
//!
//! // Symbolize the addresses for the current process, as that's what they
//! // belong to. The library also supports other symbolization sources, such as
//! // arbitrary ELF files.
//! let src = Source::Process(Process::new(Pid::Slf));
//! let symbolizer = Symbolizer::new();
//! let syms = symbolizer.symbolize(&src, Input::AbsAddr(&addrs)).unwrap();
//!
//! assert_eq!(syms.len(), 2);
//!
//! let fopen = syms[0].as_sym().unwrap();
//! assert_eq!(fopen.name, "fopen");
//!
//! let fseek = syms[1].as_sym().unwrap();
//! assert_eq!(fseek.name, "fseek");
//! ```
//!
//! The example is contrived, of course, because we already know the names
//! corresponding to the addresses, but it gets the basic workings across. Also,
//! the library not only reports the name but additional meta data such as the
//! symbol's start address and size, and even potentially inlined callees. See
//! the [`Sym`] type for details.
//!
//! In more realistic setting you can envision a backtrace being captured and
//! symbolized instead. Refer to the runnable
//! [`backtrace`](https://github.com/libbpf/blazesym/blob/main/examples/backtrace.rs)
//! example.

mod perf_map;
mod source;
mod symbolizer;

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;

cfg_apk! {
  pub use source::Apk;
}
cfg_breakpad! {
  pub use source::Breakpad;
}
pub use source::Elf;
cfg_gsym! {
  pub use source::Gsym;
  pub use source::GsymData;
  pub use source::GsymFile;
}
pub use source::Kernel;
pub use source::Process;
pub use source::Source;
pub use symbolizer::Builder;
pub use symbolizer::Symbolizer;

use crate::normalize;
use crate::Addr;
use crate::Result;


/// Options determining what "parts" of a symbol to look up.
#[derive(Debug)]
pub(crate) enum FindSymOpts {
    /// Only look up the "basic" symbol data (name, address, size, ...), without
    /// source code location and inlined function information.
    Basic,
    /// Look up symbol data and source code location information.
    CodeInfo,
    /// Look up symbol data, source code location information, and inlined
    /// function information.
    CodeInfoAndInlined,
}

impl FindSymOpts {
    #[inline]
    pub(crate) fn code_info(&self) -> bool {
        match self {
            Self::Basic => false,
            Self::CodeInfo | Self::CodeInfoAndInlined => true,
        }
    }

    #[inline]
    pub(crate) fn inlined_fns(&self) -> bool {
        match self {
            Self::Basic | Self::CodeInfo => false,
            Self::CodeInfoAndInlined => true,
        }
    }
}


/// A enumeration of the different input types the symbolization APIs
/// support.
#[derive(Clone, Copy, Debug)]
pub enum Input<T> {
    /// An absolute address.
    ///
    /// A absolute address is an address as a process would see it, for example.
    /// It may include relocation or address space randomization artifacts.
    AbsAddr(T),
    /// A virtual offset.
    ///
    /// A virtual offset is an address as it would appear in a binary or debug
    /// symbol file.
    VirtOffset(T),
    /// A file offset.
    ///
    /// A file offset is the linear offset of a symbol in a file.
    FileOffset(T),
}

impl<T> Input<T> {
    /// Extract the inner payload.
    ///
    /// ```rust
    /// # use blazesym::symbolize;
    /// let addrs = [1, 2, 3, 4];
    /// let input = symbolize::Input::FileOffset(addrs.as_slice());
    /// assert_eq!(input.into_inner(), &[1, 2, 3, 4]);
    /// ```
    #[inline]
    pub fn into_inner(self) -> T {
        match self {
            Self::AbsAddr(x) | Self::VirtOffset(x) | Self::FileOffset(x) => x,
        }
    }
}

#[cfg(test)]
impl<T> Input<&[T]>
where
    T: Copy,
{
    fn try_to_single(&self) -> Option<Input<T>> {
        match self {
            Self::AbsAddr([addr]) => Some(Input::AbsAddr(*addr)),
            Self::VirtOffset([addr]) => Some(Input::VirtOffset(*addr)),
            Self::FileOffset([offset]) => Some(Input::FileOffset(*offset)),
            _ => None,
        }
    }
}


/// Source code location information for a symbol or inlined function.
#[derive(Clone, Debug, PartialEq)]
pub struct CodeInfo<'src> {
    /// The directory in which the source file resides.
    pub dir: Option<Cow<'src, Path>>,
    /// The file that defines the symbol.
    pub file: Cow<'src, OsStr>,
    /// The line number of the symbolized instruction in the source
    /// code.
    ///
    /// This is the line number of the instruction of the address being
    /// symbolized, not the line number that defines the symbol
    /// (function).
    pub line: Option<u32>,
    /// The column number of the symbolized instruction in the source
    /// code.
    pub column: Option<u16>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl CodeInfo<'_> {
    /// Helper method to retrieve the path to the represented source file,
    /// on a best-effort basis. It depends on the symbolization source data
    /// whether this path is absolute or relative and, if its the latter, what
    /// directory it is relative to. In general this path is mostly intended for
    /// displaying purposes.
    #[inline]
    pub fn to_path(&self) -> Cow<'_, Path> {
        self.dir.as_ref().map_or_else(
            || Cow::Borrowed(Path::new(&self.file)),
            |dir| Cow::Owned(dir.join(&self.file)),
        )
    }

    /// Convert this object into one with all references converted into
    /// guaranteed owned (i.e., heap allocated) members.
    pub fn to_owned(&self) -> CodeInfo<'static> {
        CodeInfo {
            dir: self.dir.as_ref().map(|dir| Cow::Owned(dir.to_path_buf())),
            file: Cow::Owned(self.file.to_os_string()),
            line: self.line,
            column: self.column,
            _non_exhaustive: (),
        }
    }
}


/// A type representing an inlined function.
#[derive(Clone, Debug, PartialEq)]
pub struct InlinedFn<'src> {
    /// The symbol name of the inlined function.
    pub name: Cow<'src, str>,
    /// Source code location information for the call to the function.
    pub code_info: Option<CodeInfo<'src>>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}


/// The source code language from which a symbol originates.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub(crate) enum SrcLang {
    /// The language is unknown.
    #[default]
    Unknown,
    /// The language is C++.
    Cpp,
    /// The language is Rust.
    Rust,
}


/// Our internal representation of a symbol.
#[derive(Debug, PartialEq)]
pub(crate) struct IntSym<'src> {
    /// The name of the symbol.
    pub name: &'src str,
    /// The symbol's normalized address.
    pub addr: Addr,
    /// The symbol's size, if available.
    pub size: Option<usize>,
    /// The source code language from which the symbol originates.
    pub lang: SrcLang,
    /// Source code location information.
    pub code_info: Option<CodeInfo<'src>>,
    /// Inlined function information.
    pub inlined: Box<[InlinedFn<'src>]>,
}


/// The result of address symbolization by [`Symbolizer`].
#[derive(Clone, Debug, PartialEq)]
pub struct Sym<'src> {
    /// The symbol name that an address belongs to.
    pub name: Cow<'src, str>,
    /// The address at which the symbol is located (i.e., its "start").
    ///
    /// This is the "normalized" address of the symbol, as present in
    /// the file (and reported by tools such as `readelf(1)`,
    /// `llvm-gsymutil`, or similar).
    pub addr: Addr,
    /// The byte offset of the address that got symbolized from the
    /// start of the symbol (i.e., from `addr`).
    ///
    /// E.g., when normalizing address 0x1337 of a function that starts at
    /// 0x1330, the offset will be set to 0x07 (and `addr` will be 0x1330). This
    /// member is especially useful in contexts when input addresses are not
    /// already normalized, such as when normalizing an address in a process
    /// context (which may have been relocated and/or have layout randomizations
    /// applied).
    pub offset: usize,
    /// The symbol's size, if available.
    pub size: Option<usize>,
    /// Source code location information for the symbol.
    pub code_info: Option<CodeInfo<'src>>,
    /// Inlined function information, if requested and available.
    ///
    /// Availability depends on both the underlying symbolization source (e.g.,
    /// ELF does not contain inline information, but DWARF does) as well as
    /// whether a function was actually inlined at the address in question.
    ///
    /// Inlined functions are reported in the order in which their calls are
    /// nested. For example, if the instruction at the address to symbolize
    /// falls into a function `f` at an inlined call to `g`, which in turn
    /// contains an inlined call to `h`, the symbols will be reported in the
    /// order `f`, `g`, `h`.
    pub inlined: Box<[InlinedFn<'src>]>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}


/// The reason why symbolization failed.
///
/// The reason is generally only meant as a hint. Reasons reported may change
/// over time and, hence, should not be relied upon for the correctness of the
/// application.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Reason {
    /// The absolute address was not found in the corresponding process' virtual
    /// memory map.
    Unmapped,
    /// The file offset does not map to a valid piece of code/data.
    InvalidFileOffset,
    /// The `/proc/<pid>/maps` entry corresponding to the address does not have
    /// a component (file system path, object, ...) associated with it.
    MissingComponent,
    /// The symbolization source has no or no relevant symbols.
    ///
    /// This reason could for instance be used if a shared object only
    /// has dynamic symbols, but appears to be stripped aside from that.
    MissingSyms,
    /// The address belonged to an entity that is currently unsupported.
    Unsupported,
    /// The address could not be found in the symbolization source.
    UnknownAddr,
}

impl Display for Reason {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let s = match self {
            Self::Unmapped => "absolute address not found in virtual memory map of process",
            Self::InvalidFileOffset => "file offset does not map to a valid piece of code/data",
            Self::MissingComponent => "proc maps entry has no component",
            Self::MissingSyms => "symbolization source has no or no relevant symbols",
            Self::Unsupported => "address belongs to unsupprted entity",
            Self::UnknownAddr => "address not found in symbolization source",
        };

        f.write_str(s)
    }
}

impl From<normalize::Reason> for Reason {
    #[inline]
    fn from(reason: normalize::Reason) -> Self {
        match reason {
            normalize::Reason::Unmapped => Self::Unmapped,
            normalize::Reason::MissingComponent => Self::MissingComponent,
            normalize::Reason::Unsupported => Self::Unsupported,
        }
    }
}


/// An enumeration used as reporting vehicle for address symbolization.
// We keep this enum as exhaustive because additions to it, should they occur,
// are expected to be backwards-compatibility breaking.
#[derive(Clone, Debug, PartialEq)]
pub enum Symbolized<'src> {
    /// The input address was symbolized as the provided symbol.
    Sym(Sym<'src>),
    /// The input address was not found and could not be symbolized.
    ///
    /// The provided reason is a best guess, hinting at what ultimately
    /// prevented the symbolization from being successful.
    Unknown(Reason),
}

impl<'src> Symbolized<'src> {
    /// Convert the object into a [`Sym`] reference, if the corresponding
    /// variant is active.
    #[inline]
    pub fn as_sym(&self) -> Option<&Sym<'src>> {
        match self {
            Self::Sym(sym) => Some(sym),
            Self::Unknown(..) => None,
        }
    }

    /// Convert the object into a [`Sym`] object, if the corresponding variant
    /// is active.
    #[inline]
    pub fn into_sym(self) -> Option<Sym<'src>> {
        match self {
            Self::Sym(sym) => Some(sym),
            Self::Unknown(..) => None,
        }
    }
}


/// The trait for types providing address symbolization services.
pub(crate) trait Symbolize
where
    Self: Debug,
{
    /// Find the symbol corresponding to the given address.
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<IntSym<'_>, Reason>>;
}


/// A trait representing the ability to convert file offsets into virtual
/// offsets.
///
/// Please refer to the [`Input`] enum for an overview of the various offset
/// types.
pub(crate) trait TranslateFileOffset
where
    Self: Debug,
{
    /// Convert the provided file offset into a virtual offset.
    fn file_offset_to_virt_offset(&self, file_offset: u64) -> Result<Option<Addr>>;
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let lang = SrcLang::default();
        assert_ne!(format!("{lang:?}"), "");

        let input = Input::FileOffset(0x1337);
        assert_ne!(format!("{input:?}"), "");

        let code_info = CodeInfo {
            dir: Some(Cow::Borrowed(Path::new("/tmp/some-dir"))),
            file: Cow::Borrowed(OsStr::new("test.c")),
            line: Some(1337),
            column: None,
            _non_exhaustive: (),
        };

        let sym = Sym {
            name: Cow::Borrowed("test"),
            addr: 1337,
            offset: 42,
            size: None,
            code_info: None,
            inlined: Box::new([InlinedFn {
                name: Cow::Borrowed("inlined_test"),
                code_info: Some(code_info.clone()),
                _non_exhaustive: (),
            }]),
            _non_exhaustive: (),
        };
        assert_ne!(format!("{sym:?}"), "");

        let symbolized = Symbolized::Sym(sym);
        assert_ne!(format!("{symbolized:?}"), "");
    }

    /// Exercise the `Display` representation of various types.
    #[test]
    fn display_repr() {
        assert_eq!(
            Reason::MissingSyms.to_string(),
            "symbolization source has no or no relevant symbols"
        );
    }

    /// Check that we can convert `normalize::Reason` objects into
    /// `symbolize::Reason` objects.
    #[test]
    fn reason_conversion() {
        assert_eq!(Reason::from(normalize::Reason::Unmapped), Reason::Unmapped);
        assert_eq!(
            Reason::from(normalize::Reason::MissingComponent),
            Reason::MissingComponent
        );
        assert_eq!(
            Reason::from(normalize::Reason::Unsupported),
            Reason::Unsupported
        );
    }

    /// Test the `Symbolized::*_sym()` conversion methods for the `Unknown`
    /// variant.
    #[test]
    fn symbolized_unknown_conversions() {
        let symbolized = Symbolized::Unknown(Reason::UnknownAddr);
        assert_eq!(symbolized.as_sym(), None);
        assert_eq!(symbolized.into_sym(), None);
    }
}

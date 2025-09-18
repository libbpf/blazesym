//! Functionality for symbolizing addresses.
//!
//! This module contains functionality for symbolizing addresses, i.e., finding
//! symbol names and other information based on "raw" addresses.
//!
//! For example, here we symbolize the address of `libc`'s `fopen` and `fseek`
//! functions, given their addresses in the current process:
//! ```no_run
//! use blazesym::symbolize::source::Process;
//! use blazesym::symbolize::source::Source;
//! use blazesym::symbolize::Input;
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
//! the library not only reports the name but additional metadata such as the
//! symbol's start address and size, and even inlined callees if asked for and
//! available. See the [`Sym`] type for details.
//!
//! In more realistic setting you can envision a backtrace being captured and
//! symbolized instead. Refer to the runnable
//! [`backtrace`](https://github.com/libbpf/blazesym/blob/main/examples/backtrace.rs)
//! example.
//!
//! # Advanced use cases
//! In many cases symbolization is straight forward: the user provides a
//! symbolization source -- typically a file of a certain data format -- and the
//! library knows how to parse it and look up a symbol.
//!
//! ### Processes
//! However, in the case of process symbolization as briefly shown above, a
//! process is really a form of container. That is to say, it contains a set of
//! entities (e.g., loaded shared objects, otherwise mapped files etc.) that
//! addresses can fall into and that each may require different ways of
//! symbolization. **blazesym** comes with a default way of dealing with the
//! entities inside such a container, where it honors embedded symbols and debug
//! information (implicitly used in the above example), but advanced users may
//! desire more flexibility. For example, envision a case where, instead of
//! using embedded symbols in an executable, all binaries are stripped and
//! symbol information is co-located somewhere on the file system. Said symbol
//! data could also be not in the ELF or DWARF formats, but in the Gsym, which
//! is optimized for fast lookup and also typically requires much less disk
//! space.
//!
//! In such a setup, a user can install a custom process "dispatcher". This
//! dispatcher is a callback function that **blazesym** invokes and that it
//! provides certain information about the "member" that an address falls into
//! to (in the form of a [`ProcessMemberInfo`] object). It is then the
//! dispatcher's responsibility to use this information to instantiate and
//! return a "resolver" that the library will use as part of address
//! symbolization for addresses mapping to a single entity in inside the process
//! (e.g., a shared object).
//!
//! **blazesym** provides a set of resolvers, that can act as building blocks
//! for implementing a custom dispatch function. These resolver are all
//! available in the [`helper`][crate::helper] module.
//!
//! A complete example using a custom dispatch function to symbolize addresses
//! in a process after fetching their debug symbols via a
//! [`debuginfod`](https://sourceware.org/elfutils/Debuginfod.html) client is
//! available in the
//! [`sym-debuginfod`](https://github.com/libbpf/blazesym/blob/main/examples/sym-debuginfod)
//! example.
//!
//! ### APKs
//! APKs are another container format (common on Android systems) that can be
//! customized with a dispatcher. Installation of a custom dispatcher works
//! similar to the process symbolization case, the only difference is that
//! different data is provided to the dispatch function (refer to
//! [`ApkMemberInfo`]). Please refer to the
//! [`gsym-in-apk`](https://github.com/libbpf/blazesym/blob/main/examples/gsym-in-apk)
//! example, which illustrates the basic workflow.

pub mod cache;
pub mod source;
mod symbolizer;

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;
use std::str;

cfg_apk! {
    pub use symbolizer::ApkDispatch;
    pub use symbolizer::ApkMemberInfo;
}
pub use symbolizer::Builder;
pub use symbolizer::ProcessDispatch;
pub use symbolizer::ProcessMemberInfo;
pub use symbolizer::Symbolizer;

pub(crate) use symbolizer::symbolize_with_resolver;
pub(crate) use symbolizer::Resolver;

// Strictly speaking these types are applicable to the entire crate, but right
// now they are only used as part of the symbolization APIs, so we re-export
// them through this module only.
pub use crate::maps::EntryPath as ProcessMemberPath;
pub use crate::maps::PathName as ProcessMemberType;

use crate::Addr;
use crate::Result;


/// Options determining what data about a symbol to look up.
#[derive(Debug)]
#[non_exhaustive]
pub enum FindSymOpts {
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
#[derive(Clone, Copy, Debug, PartialEq)]
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
    fn map<F, U>(&self, f: F) -> Input<U>
    where
        T: Copy,
        F: FnOnce(T) -> U,
    {
        match self {
            Self::AbsAddr(x) => Input::AbsAddr(f(*x)),
            Self::VirtOffset(x) => Input::VirtOffset(f(*x)),
            Self::FileOffset(x) => Input::FileOffset(f(*x)),
        }
    }

    /// Retrieve a reference to the inner payload.
    #[inline]
    pub fn as_inner_ref(&self) -> &T {
        match self {
            Self::AbsAddr(x) | Self::VirtOffset(x) | Self::FileOffset(x) => x,
        }
    }

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
    pub fn into_owned(self) -> CodeInfo<'static> {
        let Self {
            dir,
            file,
            line,
            column,
            _non_exhaustive: (),
        } = self;

        CodeInfo {
            dir: dir.map(|dir| Cow::Owned(dir.into_owned())),
            file: Cow::Owned(file.into_owned()),
            line,
            column,
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

impl InlinedFn<'_> {
    /// Convert this object into one with all references converted into
    /// guaranteed owned (i.e., heap allocated) members.
    pub fn into_owned(self) -> InlinedFn<'static> {
        let Self {
            name,
            code_info,
            _non_exhaustive: (),
        } = self;

        InlinedFn {
            name: Cow::Owned(name.into_owned()),
            code_info: code_info.map(CodeInfo::into_owned),
            _non_exhaustive: (),
        }
    }
}


/// The source code language from which a symbol originates.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
#[non_exhaustive]
pub enum SrcLang {
    /// The language is unknown.
    #[default]
    Unknown,
    /// The language is C++.
    Cpp,
    /// The language is Rust.
    Rust,
}


/// A type representing a symbol as produced by a [`Resolve`] object.
#[derive(Debug, PartialEq)]
pub struct ResolvedSym<'src> {
    /// The name of the symbol.
    pub name: &'src str,
    /// The path to or name of the module containing the symbol.
    pub module: Option<&'src OsStr>,
    /// The symbol's normalized address.
    pub addr: Addr,
    /// The symbol's size, if available.
    pub size: Option<usize>,
    /// The source code language from which the symbol originates.
    pub lang: SrcLang,
    /// Source code location information.
    pub code_info: Option<Box<CodeInfo<'src>>>,
    /// Inlined function information.
    pub inlined: Box<[InlinedFn<'src>]>,
    /// The struct is non-exhaustive and open to extension.
    // TODO: In the future we may want to make this type exhaustive to
    //       allow users to construct it easily themselves, in order to
    //       enable usage of custom "resolvers".
    #[doc(hidden)]
    pub _non_exhaustive: (),
}


/// The result of address symbolization by [`Symbolizer`].
#[derive(Clone, Debug, PartialEq)]
pub struct Sym<'src> {
    /// The symbol name that an address belongs to.
    pub name: Cow<'src, str>,
    /// The path to or name of the module containing the symbol.
    ///
    /// Typically this would be the path to a executable or shared
    /// object. Depending on the symbol source this member may not be
    /// present or it could also just be a file name without path or a
    /// symbolic name such as `[vdso]` representing the vDSO or `[bpf]`
    /// for symbols in BPF programs. In case of an ELF file contained
    /// inside an APK, this will be an Android style path of the form
    /// `<apk>!<elf-in-apk>`. E.g., `/root/test.apk!/lib/libc.so`.
    pub module: Option<Cow<'src, OsStr>>,
    /// The address at which the symbol is located (i.e., its "start").
    ///
    /// This is the "normalized" address of the symbol, as present in
    /// the file (and reported by tools such as `readelf(1)`,
    /// `llvm-gsymutil`, or similar).
    pub addr: Addr,
    /// The byte offset of the address that got symbolized from the
    /// start of the symbol (i.e., from `addr`).
    ///
    /// E.g., when symbolizing address 0x1337 of a function that starts at
    /// 0x1330, the offset will be set to 0x07 (and `addr` will be 0x1330). This
    /// member is especially useful in contexts when input addresses are not
    /// already normalized, such as when symbolizing an address in a process
    /// context (which may have been relocated and/or have layout randomizations
    /// applied).
    pub offset: usize,
    /// The symbol's size, if available.
    pub size: Option<usize>,
    /// Source code location information for the symbol.
    pub code_info: Option<Box<CodeInfo<'src>>>,
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

impl Sym<'_> {
    /// Convert this object into one with all references converted into
    /// guaranteed owned (i.e., heap allocated) members.
    pub fn into_owned(self) -> Sym<'static> {
        let Self {
            name,
            module,
            addr,
            offset,
            size,
            code_info,
            inlined,
            _non_exhaustive,
        } = self;

        Sym {
            name: Cow::Owned(name.into_owned()),
            module: module.map(|module| Cow::Owned(module.into_owned())),
            addr,
            offset,
            size,
            code_info: code_info.map(|info| Box::new(info.into_owned())),
            inlined: Vec::from(inlined)
                .into_iter()
                .map(InlinedFn::into_owned)
                .collect::<Box<[_]>>(),
            _non_exhaustive: (),
        }
    }
}


/// The reason why symbolization failed.
///
/// The reason is generally only meant as a hint. Reasons reported may change
/// over time and, hence, should not be relied upon for the correctness of the
/// application.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
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

impl Reason {
    #[doc(hidden)]
    #[inline]
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Unmapped => b"absolute address not found in virtual memory map of process\0",
            Self::InvalidFileOffset => b"file offset does not map to a valid piece of code/data\0",
            Self::MissingComponent => b"proc maps entry has no component\0",
            Self::MissingSyms => b"symbolization source has no or no relevant symbols\0",
            Self::Unsupported => b"address belongs to unsupported entity\0",
            Self::UnknownAddr => b"address not found in symbolization source\0",
        }
    }
}

impl Display for Reason {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let cstr = self.as_bytes();
        // SAFETY: `as_bytes` always returns a valid string.
        let s = unsafe { str::from_utf8_unchecked(&cstr[..cstr.len() - 1]) };

        f.write_str(s)
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


/// A trait helping with upcasting into a `dyn Symbolize`.
// TODO: This trait is currently necessary because Rust does not yet support
//       trait upcasting on stable (check `trait_upcasting` feature).
#[doc(hidden)]
pub trait AsSymbolize {
    fn as_symbolize(&self) -> &dyn Symbolize;
}

/// The trait for types providing address symbolization services.
pub trait Symbolize
where
    Self: AsSymbolize + Debug,
{
    /// Find the symbol corresponding to the given address.
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>>;
}

impl<S> AsSymbolize for S
where
    S: Symbolize,
{
    fn as_symbolize(&self) -> &dyn Symbolize {
        self
    }
}


/// A meta-trait encompassing functionality necessary for plugging into
/// the container symbolization logic.
///
/// Refer to [`Builder::set_apk_dispatcher`] and
/// [`Builder::set_process_dispatcher`] for additional details.
pub trait Resolve: Symbolize + TranslateFileOffset {}

impl<R> Resolve for R where R: Symbolize + TranslateFileOffset {}


/// A trait representing the ability to convert file offsets into virtual
/// offsets.
///
/// Please refer to the [`Input`] enum for an overview of the various offset
/// types.
pub trait TranslateFileOffset
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
            module: Some(Cow::Borrowed(OsStr::new("module"))),
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

    /// Test forcing a double check of all `Sym` size changes.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn sym_size() {
        assert_eq!(size_of::<Sym>(), 104);
    }

    /// Check that [`Sym::into_owned`] works as expected.
    #[test]
    fn owned_conversion() {
        let sym = Sym {
            name: Cow::Borrowed("test"),
            module: Some(Cow::Borrowed(OsStr::new("module"))),
            addr: 1337,
            offset: 42,
            size: None,
            code_info: None,
            inlined: Box::new([InlinedFn {
                name: Cow::Borrowed("inlined_test"),
                code_info: Some(CodeInfo {
                    dir: Some(Cow::Borrowed(Path::new("/tmp/some-dir"))),
                    file: Cow::Borrowed(OsStr::new("test.c")),
                    line: Some(1337),
                    column: None,
                    _non_exhaustive: (),
                }),
                _non_exhaustive: (),
            }]),
            _non_exhaustive: (),
        };

        assert_eq!(sym, sym.clone().into_owned());
    }

    /// Check that the [`Input::map`] helper works as expected.
    #[test]
    fn input_mapping() {
        fn test<F>(f: F)
        where
            F: Fn(usize) -> Input<usize>,
        {
            let input = f(0x1337);
            let input = input.map(|x| 2 * x);
            assert_eq!(input, f(2 * 0x1337));
            assert_eq!(input.into_inner(), 2 * 0x1337);
        }

        for variant in [Input::AbsAddr, Input::VirtOffset, Input::FileOffset] {
            let () = test(variant);
        }
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

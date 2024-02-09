use std::cmp::min;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::PathBuf;

use crate::Pid;

#[cfg(doc)]
use super::Symbolizer;


cfg_apk! {
/// A single APK file.
///
/// This type is used in the [`Source::Apk`] variant.
#[derive(Clone)]
pub struct Apk {
    /// The path to an APK file.
    pub path: PathBuf,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    ///
    /// On top of this runtime configuration, the crate needs to be
    /// built with the `dwarf` feature to actually consult debug
    /// symbols. If neither is satisfied, ELF symbols will be used.
    pub debug_syms: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Apk {
    /// Create a new [`Apk`] object, referencing the provided path.
    ///
    /// `debug_syms` defaults to `true` when using this constructor.
    #[inline]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            debug_syms: true,
            _non_exhaustive: (),
        }
    }
}

impl From<Apk> for Source<'static> {
    #[inline]
    fn from(apk: Apk) -> Self {
        Source::Apk(apk)
    }
}

impl Debug for Apk {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            path,
            debug_syms: _,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Apk)).field(path).finish()
    }
}
}


cfg_breakpad! {
/// A single Breakpad file.
///
/// This type is used in the [`Source::Breakpad`] variant.
#[derive(Clone)]
pub struct Breakpad {
    /// The path to a Breakpad file.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Breakpad {
    /// Create a new [`Breakpad`] object, referencing the provided path.
    #[inline]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl From<Breakpad> for Source<'static> {
    #[inline]
    fn from(breakpad: Breakpad) -> Self {
        Source::Breakpad(breakpad)
    }
}

impl Debug for Breakpad {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            path,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Breakpad)).field(path).finish()
    }
}
}


/// A single ELF file.
///
/// This type is used in the [`Source::Elf`] variant.
#[derive(Clone)]
pub struct Elf {
    /// The path to an ELF file.
    pub path: PathBuf,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    ///
    /// On top of this runtime configuration, the crate needs to be
    /// built with the `dwarf` feature to actually consult debug
    /// symbols. If neither is satisfied, ELF symbols will be used.
    pub debug_syms: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Elf {
    /// Create a new [`Elf`] object, referencing the provided path.
    ///
    /// `debug_syms` defaults to `true` when using this constructor.
    #[inline]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            debug_syms: true,
            _non_exhaustive: (),
        }
    }
}

impl From<Elf> for Source<'static> {
    #[inline]
    fn from(elf: Elf) -> Self {
        Source::Elf(elf)
    }
}

impl Debug for Elf {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            path,
            debug_syms: _,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Elf)).field(path).finish()
    }
}


/// Linux Kernel's binary image and a copy of `/proc/kallsyms`.
///
/// This type is used in the [`Source::Kernel`] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct Kernel {
    /// The path of a kallsyms copy.
    ///
    /// For the running kernel on the device, it can be
    /// "/proc/kallsyms".  However, you can make a copy for later.
    /// In that situation, you should give the path of the
    /// copy.  Passing `None`, by default, will be
    /// `"/proc/kallsyms"`.
    pub kallsyms: Option<PathBuf>,
    /// The path of a kernel image.
    ///
    /// This should be the path of a kernel image.  For example,
    /// `"/boot/vmlinux-xxxx"`.  A `None` value will find the
    /// kernel image of the running kernel in `"/boot/"` or
    /// `"/usr/lib/debug/boot/"`.
    pub kernel_image: Option<PathBuf>,
    /// Whether or not to consult debug symbols from `kernel_image`
    /// to satisfy the request (if present).
    ///
    /// On top of this runtime configuration, the crate needs to be
    /// built with the `dwarf` feature to actually consult debug
    /// symbols. If neither is satisfied, ELF symbols will be used.
    pub debug_syms: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Default for Kernel {
    fn default() -> Self {
        Self {
            kallsyms: None,
            kernel_image: None,
            debug_syms: true,
            _non_exhaustive: (),
        }
    }
}

impl From<Kernel> for Source<'static> {
    #[inline]
    fn from(kernel: Kernel) -> Self {
        Source::Kernel(kernel)
    }
}


/// Configuration for process based address symbolization.
///
/// This type is used in the [`Source::Process`] variant.
///
/// The corresponding addresses supplied to [`Symbolizer::symbolize`] are
/// expected to be absolute addresses
/// ([`Input::AbsAddr`][crate::symbolize::Input::AbsAddr]) as valid within the
/// process identified by the [`pid`][Process::pid] member.
#[derive(Clone)]
pub struct Process {
    /// The referenced process' ID.
    pub pid: Pid,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    ///
    /// On top of this runtime configuration, the crate needs to be
    /// built with the `dwarf` feature to actually consult debug
    /// symbols. If neither is satisfied, ELF symbols will be used.
    pub debug_syms: bool,
    /// Whether to incorporate a process' [perf map][] file into the
    /// symbolization procedure.
    ///
    /// Perf map files mostly have relevance in just-in-time compiled languages,
    /// where they provide an interface for the runtime to expose addresses of
    /// dynamic symbols to profiling tools.
    ///
    /// [perf map]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jit-interface.txt
    pub perf_map: bool,
    /// Whether to work with `/proc/<pid>/map_files/` entries or with
    /// symbolic paths mentioned in `/proc/<pid>/maps` instead.
    /// `map_files` usage is generally strongly encouraged, as symbolic
    /// path usage is unlikely to work reliably in mount namespace
    /// contexts or when files have been deleted from the file system.
    /// However, by using symbolic paths the need for requiring the
    /// `SYS_ADMIN` capability is eliminated.
    pub map_files: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Process {
    /// Create a new [`Process`] object using the provided `pid`.
    ///
    /// `debug_syms` and `perf_map` default to `true` when using this
    /// constructor.
    #[inline]
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            debug_syms: true,
            perf_map: true,
            map_files: true,
            _non_exhaustive: (),
        }
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            pid,
            debug_syms: _,
            perf_map: _,
            map_files: _,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Process))
            // We use the `Display` representation here.
            .field(&format_args!("{pid}"))
            .finish()
    }
}

impl From<Process> for Source<'static> {
    #[inline]
    fn from(process: Process) -> Self {
        Source::Process(process)
    }
}


cfg_gsym! {
/// Enumeration of supported Gsym sources.
///
/// This type is used in the [`Source::Gsym`] variant.
#[derive(Clone)]
pub enum Gsym<'dat> {
    /// "Raw" Gsym data.
    Data(GsymData<'dat>),
    /// A Gsym file.
    File(GsymFile),
}

impl Debug for Gsym<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Data(data) => Debug::fmt(data, f),
            Self::File(file) => Debug::fmt(file, f),
        }
    }
}

impl<'dat> From<Gsym<'dat>> for Source<'dat> {
    #[inline]
    fn from(gsym: Gsym<'dat>) -> Self {
        Source::Gsym(gsym)
    }
}


/// Gsym data.
#[derive(Clone)]
pub struct GsymData<'dat> {
    /// The "raw" Gsym data.
    pub data: &'dat [u8],
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl<'dat> GsymData<'dat> {
    /// Create a new [`GsymData`] object, referencing the provided path.
    #[inline]
    pub fn new(data: &'dat [u8]) -> Self {
        Self {
            data,
            _non_exhaustive: (),
        }
    }
}

impl Debug for GsymData<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            data,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(GsymData))
            .field(&data.get(0..(min(data.len(), 32))).unwrap_or_default())
            .finish()
    }
}

impl<'dat> From<GsymData<'dat>> for Source<'dat> {
    #[inline]
    fn from(gsym: GsymData<'dat>) -> Self {
        Source::Gsym(Gsym::Data(gsym))
    }
}


/// A Gsym file.
#[derive(Clone)]
pub struct GsymFile {
    /// The path to the Gsym file.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl GsymFile {
    /// Create a new [`GsymFile`] object, referencing the provided path.
    #[inline]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl Debug for GsymFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            path,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(GsymFile)).field(path).finish()
    }
}

impl From<GsymFile> for Source<'static> {
    #[inline]
    fn from(gsym: GsymFile) -> Self {
        Source::Gsym(Gsym::File(gsym))
    }
}
}


/// The description of a source of symbols and debug information.
///
/// The source of symbols and debug information can be an ELF file, kernel
/// image, or process.
#[derive(Clone)]
#[non_exhaustive]
pub enum Source<'dat> {
    /// A single APK file.
    #[cfg(feature = "apk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "apk")))]
    Apk(Apk),
    /// A single Breakpad file.
    #[cfg(feature = "breakpad")]
    #[cfg_attr(docsrs, doc(cfg(feature = "breakpad")))]
    Breakpad(Breakpad),
    /// A single ELF file.
    Elf(Elf),
    /// Information about the Linux kernel.
    Kernel(Kernel),
    /// Information about a process.
    Process(Process),
    /// A Gsym file.
    #[cfg(feature = "gsym")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gsym")))]
    Gsym(Gsym<'dat>),
    #[doc(hidden)]
    Phantom(&'dat ()),
}

impl Debug for Source<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            #[cfg(feature = "apk")]
            Self::Apk(apk) => Debug::fmt(apk, f),
            #[cfg(feature = "breakpad")]
            Self::Breakpad(breakpad) => Debug::fmt(breakpad, f),
            Self::Elf(elf) => Debug::fmt(elf, f),
            Self::Kernel(kernel) => Debug::fmt(kernel, f),
            Self::Process(process) => Debug::fmt(process, f),
            #[cfg(feature = "gsym")]
            Self::Gsym(gsym) => Debug::fmt(gsym, f),
            Self::Phantom(()) => unreachable!(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let apk = Apk::new("/a-path/with/components.apk");
        assert_eq!(format!("{apk:?}"), "Apk(\"/a-path/with/components.apk\")");
        let src = Source::from(apk);
        assert_eq!(format!("{src:?}"), "Apk(\"/a-path/with/components.apk\")");

        let breakpad = Breakpad::new("/a-path/with/components.sym");
        assert_eq!(
            format!("{breakpad:?}"),
            "Breakpad(\"/a-path/with/components.sym\")"
        );
        let src = Source::from(breakpad);
        assert_eq!(
            format!("{src:?}"),
            "Breakpad(\"/a-path/with/components.sym\")"
        );

        let elf = Elf::new("/a-path/with/components.elf");
        assert_eq!(format!("{elf:?}"), "Elf(\"/a-path/with/components.elf\")");
        let src = Source::from(elf);
        assert_eq!(format!("{src:?}"), "Elf(\"/a-path/with/components.elf\")");

        let gsym_data = GsymData::new(b"12345");
        assert_eq!(format!("{gsym_data:?}"), "GsymData([49, 50, 51, 52, 53])");
        let gsym = Gsym::Data(gsym_data.clone());
        assert_eq!(format!("{gsym:?}"), "GsymData([49, 50, 51, 52, 53])");

        let gsym_file = GsymFile::new("/a-path/gsym");
        assert_eq!(format!("{gsym_file:?}"), "GsymFile(\"/a-path/gsym\")");
        let gsym = Gsym::File(gsym_file);
        assert_eq!(format!("{gsym:?}"), "GsymFile(\"/a-path/gsym\")");
        let src = Source::from(gsym);
        assert_eq!(format!("{src:?}"), "GsymFile(\"/a-path/gsym\")");
        let src = Source::from(Gsym::Data(gsym_data));
        assert_eq!(format!("{src:?}"), "GsymData([49, 50, 51, 52, 53])");

        let kernel = Kernel::default();
        assert_ne!(format!("{kernel:?}"), "");
        let src = Source::from(kernel);
        assert_ne!(format!("{src:?}"), "");

        let process = Process::new(Pid::Slf);
        assert_eq!(format!("{process:?}"), "Process(self)");
        let process = Process::new(Pid::from(1234));
        assert_eq!(format!("{process:?}"), "Process(1234)");
        let src = Source::from(process);
        assert_eq!(format!("{src:?}"), "Process(1234)");
    }
}

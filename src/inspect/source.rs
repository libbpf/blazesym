use std::path::Path;
use std::path::PathBuf;


cfg_breakpad! {
/// A Breakpad file.
#[derive(Clone, Debug, PartialEq)]
pub struct Breakpad {
    /// The path to the Breakpad (*.sym) file.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Breakpad {
    /// Create a new [`Breakpad`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl From<Breakpad> for Source {
    fn from(breakpad: Breakpad) -> Self {
        Source::Breakpad(breakpad)
    }
}
}


/// An ELF file.
#[derive(Clone, Debug, PartialEq)]
pub struct Elf {
    /// The path to the ELF file.
    pub path: PathBuf,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    pub debug_syms: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Elf {
    /// Create a new [`Elf`] object, referencing the provided path.
    ///
    /// `debug_syms` defaults to `true` when using this constructor.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            debug_syms: true,
            _non_exhaustive: (),
        }
    }
}

impl From<Elf> for Source {
    fn from(elf: Elf) -> Self {
        Source::Elf(elf)
    }
}


/// The source to use for the inspection request.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Source {
    /// The source is a Breakpad file.
    #[cfg(feature = "breakpad")]
    #[cfg_attr(docsrs, doc(cfg(feature = "breakpad")))]
    Breakpad(Breakpad),
    /// The source is an ELF file.
    Elf(Elf),
}

impl Source {
    /// Retrieve the path to the source, if it has any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            #[cfg(feature = "breakpad")]
            Self::Breakpad(breakpad) => Some(&breakpad.path),
            Self::Elf(elf) => Some(&elf.path),
        }
    }
}

//! Definitions of supported inspection sources.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;
use std::path::PathBuf;

#[cfg(doc)]
use super::Inspector;


cfg_breakpad! {
/// A Breakpad file.
#[derive(Clone, PartialEq)]
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
        Self::Breakpad(breakpad)
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


/// An ELF file.
#[derive(Clone, PartialEq)]
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
        Self::Elf(elf)
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


/// The source to use for the inspection request.
///
/// Objects of this type are used first and foremost with the
/// [`Inspector::lookup`] and [`Inspector::for_each`] methods.
#[derive(Clone, PartialEq)]
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

impl Debug for Source {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            #[cfg(feature = "breakpad")]
            Self::Breakpad(breakpad) => Debug::fmt(breakpad, f),
            Self::Elf(elf) => Debug::fmt(elf, f),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
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
    }
}

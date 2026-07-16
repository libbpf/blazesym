//! Definitions of symbolization eviction targets.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::PathBuf;

use crate::Pid;


/// Configuration for eviction of ELF related data.
#[derive(Clone)]
pub struct Elf {
    /// The path to an ELF file.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Elf {
    /// Create a new [`Elf`] object, referencing the provided path.
    #[inline]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            _non_exhaustive: (),
        }
    }
}

impl From<Elf> for Evict {
    #[inline]
    fn from(elf: Elf) -> Self {
        Self::Elf(elf)
    }
}

impl Debug for Elf {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            path,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Elf)).field(path).finish()
    }
}


/// Configuration for eviction of process-level data.
#[derive(Clone)]
pub struct Process {
    /// The referenced process' ID.
    pub pid: Pid,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Process {
    /// Create a new [`Process`] object using the provided `pid`.
    #[inline]
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            _non_exhaustive: (),
        }
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            pid,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Process))
            .field(&format_args!("{pid}"))
            .finish()
    }
}

impl From<Process> for Evict {
    #[inline]
    fn from(process: Process) -> Self {
        Self::Process(process)
    }
}


/// A description of what previously cached data to evict.
#[derive(Clone)]
#[non_exhaustive]
pub enum Evict {
    /// Data cached for an ELF file.
    Elf(Elf),
    /// Data cached for a process.
    Process(Process),
}

impl Debug for Evict {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Elf(elf) => Debug::fmt(elf, f),
            Self::Process(process) => Debug::fmt(process, f),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let elf = Elf::new("/foobar/baz");
        assert_eq!(format!("{elf:?}"), "Elf(\"/foobar/baz\")");
        let evict = Evict::from(elf);
        assert_eq!(format!("{evict:?}"), "Elf(\"/foobar/baz\")");

        let process = Process::new(Pid::Slf);
        assert_eq!(format!("{process:?}"), "Process(self)");
        let process = Process::new(Pid::from(1234));
        assert_eq!(format!("{process:?}"), "Process(1234)");
        let evict = Evict::from(process);
        assert_eq!(format!("{evict:?}"), "Process(1234)");
    }
}

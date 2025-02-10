//! Definitions of symbolization caching targets.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;

use crate::Pid;


/// Configuration for caching of process-level data.
#[derive(Clone)]
pub struct Process {
    /// The referenced process' ID.
    pub pid: Pid,
    /// Whether to cache the process' VMAs for later use.
    ///
    /// Caching VMAs can be useful, because it conceptually enables the
    /// library to serve a symbolization request targeting a process
    /// even if said process has since exited the system.
    ///
    /// Note that once VMAs have been cached this way, the library will
    /// refrain from re-reading updated VMAs unless instructed to.
    /// Hence, if you have reason to believe that a process may have
    /// changed its memory regions (by loading a new shared object, for
    /// example), you would have to make another request to cache them
    /// yourself.
    ///
    /// Note furthermore that if you cache VMAs to later symbolize
    /// addresses after the original process has already exited, you
    /// will have to opt-out of usage of `/proc/<pid>/map_files/` as
    /// part of the symbolization request. Refer to
    /// [`source::Process::map_files`][crate::symbolize::source::Process::map_files].
    pub cache_vmas: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Process {
    /// Create a new [`Process`] object using the provided `pid`.
    ///
    /// `cache_vmas` default to `true` when using this constructor.
    #[inline]
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            cache_vmas: true,
            _non_exhaustive: (),
        }
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            pid,
            cache_vmas: _,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Process))
            .field(&format_args!("{pid}"))
            .finish()
    }
}

impl From<Process> for Cache<'static> {
    #[inline]
    fn from(process: Process) -> Self {
        Self::Process(process)
    }
}


/// A description of what data to use to cache in advance, so that
/// subsequent symbolization requests can be satisfied quicker.
#[derive(Clone)]
#[non_exhaustive]
pub enum Cache<'dat> {
    /// Information about a process.
    Process(Process),
    #[doc(hidden)]
    Phantom(&'dat ()),
}

impl Debug for Cache<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Process(process) => Debug::fmt(process, f),
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
        let process = Process::new(Pid::Slf);
        assert_eq!(format!("{process:?}"), "Process(self)");
        let process = Process::new(Pid::from(1234));
        assert_eq!(format!("{process:?}"), "Process(1234)");
        let cache = Cache::from(process);
        assert_eq!(format!("{cache:?}"), "Process(1234)");
    }
}

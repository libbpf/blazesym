use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::num::NonZeroU32;
use std::process;


/// An enumeration identifying a process.
#[derive(Clone, Copy, Debug)]
pub enum Pid {
    /// The current process.
    Slf,
    /// The process identified by the provided ID.
    Pid(NonZeroU32),
}

impl Pid {
    /// Resolve this [`Pid`] into an actual number, if it is the symbolic
    /// [`Pid::Slf`] variant.
    pub(crate) fn resolve(&self) -> u32 {
        match self {
            Self::Slf => process::id(),
            Self::Pid(pid) => pid.get(),
        }
    }
}

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Slf => write!(f, "self"),
            Self::Pid(pid) => write!(f, "{pid}"),
        }
    }
}

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        NonZeroU32::new(pid).map(Pid::Pid).unwrap_or(Pid::Slf)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::read_link;


    fn resolve_pid() -> u32 {
        let path = read_link("/proc/self").unwrap();
        let file = path.file_name().unwrap();
        let name = file.to_str().unwrap();
        let pid = name.parse::<u32>().unwrap();
        pid
    }


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let pid = Pid::Slf;
        assert_ne!(format!("{pid:?}"), "");
    }

    /// Check that we can resolve a symbolic PID name.
    #[test]
    fn pid_resolution() {
        let pid = Pid::Slf.resolve();
        assert_eq!(pid, resolve_pid());
    }
}

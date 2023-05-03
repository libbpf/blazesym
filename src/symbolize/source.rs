use std::path::PathBuf;

use crate::Addr;
use crate::Pid;

#[cfg(doc)]
use super::Symbolizer;


/// A single ELF file.
#[derive(Clone, Debug)]
pub struct Elf {
    /// The name of ELF file.
    ///
    /// It can be an executable or shared object.
    /// For example, passing `"/bin/sh"` will load symbols and debug information from `sh`.
    /// Whereas passing `"/lib/libc.so.xxx"` will load symbols and debug information from the libc.
    pub path: PathBuf,
    /// The address where the executable segment loaded.
    ///
    /// The address in the process should be the executable segment's
    /// first byte.  For example, in `/proc/<pid>/maps`.
    ///
    /// ```text
    ///     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    /// ```
    ///
    /// It reveals that the executable segment of libc-2.28.so was
    /// loaded at 0x7fe1b2dc4000.  This base address is used to
    /// translate an address in the segment to the corresponding
    /// address in the ELF file.
    ///
    /// A loader would load an executable segment with the permission of
    /// `x`.  For example, the first block is with the permission of
    /// `r-xp`.
    pub base_address: Addr,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Elf {
    /// Create a new [`Elf`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            base_address: 0,
            _non_exhaustive: (),
        }
    }
}

impl From<Elf> for Source {
    fn from(elf: Elf) -> Self {
        Source::Elf(elf)
    }
}


/// Linux Kernel's binary image and a copy of /proc/kallsyms
#[derive(Clone, Debug, Default)]
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
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl From<Kernel> for Source {
    fn from(kernel: Kernel) -> Self {
        Source::Kernel(kernel)
    }
}


/// Configuration for process based address symbolization.
///
/// The corresponding addresses supplied to [`Symbolizer::symbolize`] are
/// expected to be absolute addresses as valid within the process identified
/// by the [`pid`][Process::pid] member.
#[derive(Clone, Debug)]
pub struct Process {
    /// The referenced process' ID.
    pub pid: Pid,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Process {
    /// Create a new [`Process`] object using the provided `pid`.
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            _non_exhaustive: (),
        }
    }
}

impl From<Process> for Source {
    fn from(process: Process) -> Self {
        Source::Process(process)
    }
}


/// A gsym file.
#[derive(Clone, Debug)]
pub struct Gsym {
    /// The path to the gsym file.
    pub path: PathBuf,
    /// The base address.
    pub base_address: Addr,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl Gsym {
    /// Create a new [`Gsym`] object, referencing the provided path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            base_address: 0,
            _non_exhaustive: (),
        }
    }
}

impl From<Gsym> for Source {
    fn from(gsym: Gsym) -> Self {
        Source::Gsym(gsym)
    }
}


/// The description of a source of symbols and debug information.
///
/// The source of symbols and debug information can be an ELF file, kernel
/// image, or process.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Source {
    /// A single ELF file
    Elf(Elf),
    /// Information about the Linux kernel.
    Kernel(Kernel),
    /// Information about a process.
    Process(Process),
    /// A gsym file.
    Gsym(Gsym),
}

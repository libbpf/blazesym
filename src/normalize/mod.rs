//! Functionality for address normalization.
//!
//! Address normalization is one step of address symbolization. Typically only
//! used internally, it is also made accessible for users to enable remote
//! symbolization work flows. Remote symbolization refers to performing
//! symbolization on a system other than where the "raw" addresses were
//! originally captured. This is useful when working with embedded or locked
//! down systems, for example, where files necessary to perform the
//! symbolization are not available or not accessible.
//!
//! In such a setting address normalization would happen on the embedded device.
//! The result of this normalization would then be transferred to another one
//! that actually performs the symbolization.
//!
//! The [output][UserOutput] of address normalization is a set of file offsets
//! along with meta data. The meta data is expected to contain sufficient
//! information to identify the symbolization source to use (e.g., the ELF file
//! with symbols) on the symbolizing system.
//!
//! ```no_run
//! use blazesym::normalize::Normalizer;
//! use blazesym::Addr;
//! use blazesym::Pid;
//!
//! let normalizer = Normalizer::new();
//! let fopen_addr = libc::fopen as Addr;
//! let addrs = [fopen_addr];
//! let pid = Pid::Slf;
//! let normalized = normalizer.normalize_user_addrs(pid, &addrs).unwrap();
//! assert_eq!(normalized.outputs.len(), 1);
//!
//! let (file_offset, meta_idx) = normalized.outputs[0];
//! // fopen (0x7f5f8e23a790) corresponds to file offset 0x77790 within
//! // Elf(Elf { path: "/usr/lib64/libc.so.6", build_id: Some([...]), ... })
//! println!(
//!   "fopen ({fopen_addr:#x}) corresponds to file offset {file_offset:#x} within {:?}",
//!   normalized.meta[meta_idx]
//! );
//! ```

pub(crate) mod buildid;
mod meta;
mod normalizer;
mod user;

use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::str;

pub use meta::Apk;
pub use meta::Elf;
pub use meta::Unknown;
pub use meta::UserMeta;
pub use normalizer::Builder;
pub use normalizer::Normalizer;
// For reasons unknown, we need to `pub use` this type here or the documentation
// will not resolve links. See https://github.com/rust-lang/rust/issues/116854
#[doc(hidden)]
pub use normalizer::Output;
pub use user::UserOutput;

pub(crate) use user::normalize_sorted_user_addrs_with_entries;
pub(crate) use user::Handler;


/// Options influencing the address normalization process.
#[derive(Clone, Debug, Default)]
pub struct NormalizeOpts {
    /// Whether or not addresses are sorted (in ascending order) already.
    ///
    /// Normalization always happens on sorted addresses and if the addresses
    /// are sorted already, the library does not need to sort and later restore
    /// original ordering, speeding up the normalization process.
    pub sorted_addrs: bool,
    /// Whether to report `/proc/<pid>/map_files/` entry paths or work
    /// with symbolic paths mentioned in `/proc/<pid>/maps` instead.
    ///
    /// Relying on `map_files` may make sense in cases where
    /// symbolization happens on the local system and the reported paths
    /// can be worked with directly. In most other cases where one wants
    /// to attach meaning to symbolic paths on a remote system (e.g., by
    /// using them for file look up) symbolic paths are probably the
    /// better choice.
    pub map_files: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}


/// The reason why normalization failed.
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
    /// The `/proc/<pid>/maps` entry corresponding to the address does not have
    /// a component (file system path, object, ...) associated with it.
    MissingComponent,
    /// The address belonged to an entity that is currently unsupported.
    Unsupported,
}

impl Reason {
    #[doc(hidden)]
    #[inline]
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Unmapped => b"absolute address not found in virtual memory map of process\0",
            Self::MissingComponent => b"proc maps entry has no component\0",
            Self::Unsupported => b"address belongs to unsupported entity\0",
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


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Display` representation of various types.
    #[test]
    fn display_repr() {
        assert_eq!(
            Reason::Unmapped.to_string(),
            "absolute address not found in virtual memory map of process"
        );
        assert_eq!(
            Reason::MissingComponent.to_string(),
            "proc maps entry has no component"
        );
        assert_eq!(
            Reason::Unsupported.to_string(),
            "address belongs to unsupported entity"
        );
    }
}

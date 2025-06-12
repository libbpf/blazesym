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
//!
//! # Notes
//! Please note that **blazesym** does not concern itself with the transfer of
//! data between systems. That is a task that is entirely in user's hands.

pub(crate) mod buildid;
pub(crate) mod ioctl;
mod meta;
mod normalizer;
mod user;

use crate::symbolize;

cfg_apk! {
pub use meta::Apk;
}
pub use meta::Elf;
pub use meta::Unknown;
pub use meta::UserMeta;
pub use normalizer::Builder;
pub use normalizer::Normalizer;
// For reasons unknown, we need to `pub use` this type here or the documentation
// will not resolve links. See https://github.com/rust-lang/rust/issues/116854
#[doc(hidden)]
pub use normalizer::Output;
pub use symbolize::Reason;
pub use user::UserOutput;

pub(crate) use user::normalize_sorted_user_addrs_with_entries;
pub(crate) use user::Handler;


/// Options influencing the address normalization process.
///
/// By default all options are disabled.
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
    /// Normalize addresses inside APKs to the contained ELF file and
    /// report a regular [`Elf`] meta data entry instead of an [`Apk`]
    /// one. As a result, the reported file offset will also be relative
    /// to the contained ELF file and not to the APK itself.
    #[cfg(feature = "apk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "apk")))]
    pub apk_to_elf: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

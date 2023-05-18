//! Functionality for address normalization.
//!
//! Address normalization is one step of address symbolization: before can
//! address as captured in a process can be looked up in a file, it needs to be
//! converted into an address as it will be used inside the file. E.g.,
//! addresses in a shared object (or any position independent binary) may be
//! relative to that file. When such a shared object is loaded into a process,
//! it is relocated. Normalization removes this relocation information and
//! similar adjustments made by the system (e.g., by address space layout
//! randomization).
//!
//! ```no_run
//! use blazesym::normalize::Normalizer;
//! use blazesym::Pid;
//!
//! let normalizer = Normalizer::new();
//! let addrs = [0xdeadbeef];
//! let pid = Pid::from(1234);
//! let norm_addrs = normalizer.normalize_user_addrs(&addrs, pid).unwrap();
//! ```

mod meta;
mod normalizer;

pub use meta::Binary;
pub use meta::Unknown;
pub use meta::UserAddrMeta;
pub use normalizer::NormalizedUserAddrs;
pub use normalizer::Normalizer;

pub(crate) use normalizer::normalize_elf_addr;
pub(crate) use normalizer::normalize_sorted_user_addrs_with_entries;
pub(crate) use normalizer::Handler;

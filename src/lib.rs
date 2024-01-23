//! **blazesym** is a library that can be used to symbolize addresses. Address
//! symbolization is a common problem in tracing contexts, for example, where
//! users want to reason about functions by name, but low level components
//! report only the "raw" addresses (e.g., in the form of stacktraces).
//!
//! In addition to symbolization, **blazesym** also provides APIs for the
//! reverse operation: looking up addresses from symbol names. That can be
//! useful, for example, for configuring breakpoints or tracepoints.
//!
//! ## Overview
//! The crate is organized via public modules that expose functionality
//! pertaining a certain topic. Specifically, these areas are currently covered:
//!
//! - [`symbolize`] covers address symbolization functionality
//! - [`inspect`] contains APIs for inspecting files such as ELF and Gsym to
//!   lookup addresses to symbol names, for example
//! - [`normalize`] exposes address normalization functionality
//!
//! C API bindings are defined in a cross-cutting manner as part of the
//! `cblazesym` crate (note that Rust code should not have to consume
//! these functions and on the ABI level this module organization has no
//! relevance for C).

#![allow(
    clippy::collapsible_if,
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    clippy::absolute_paths,
    rustdoc::broken_intra_doc_links
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(
    not(all(feature = "apk", feature = "dwarf", feature = "gsym")),
    allow(dead_code, unused_imports)
)]


#[cfg(feature = "nightly")]
extern crate test;

#[macro_use]
mod cfg;
#[cfg(feature = "breakpad")]
mod breakpad;
#[cfg(feature = "dwarf")]
mod dwarf;
mod elf;
mod error;
mod file_cache;
#[cfg(feature = "gsym")]
mod gsym;
mod insert_map;
pub mod inspect;
mod kernel;
mod ksym;
mod maps;
mod mmap;
pub mod normalize;
mod once;
mod pid;
mod resolver;
pub mod symbolize;
mod util;
#[cfg(feature = "apk")]
mod zip;

use std::result;

use resolver::SymResolver;


pub use crate::error::Error;
pub use crate::error::ErrorExt;
pub use crate::error::ErrorKind;
pub use crate::error::IntoError;
pub use crate::pid::Pid;

/// A result type using our [`Error`] by default.
pub type Result<T, E = Error> = result::Result<T, E>;


/// A type representing addresses.
pub type Addr = u64;


/// The type of a symbol.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SymType {
    /// The symbol type is unspecified or unknown.
    ///
    /// In input contexts this variant can be used to encompass all
    /// other variants (functions and variables), whereas in output
    /// contexts it means that the type is not known.
    #[default]
    Undefined,
    /// The symbol is a function.
    Function,
    /// The symbol is a variable.
    Variable,
}


/// Utility functionality not specific to any overarching theme.
pub mod helper {
    pub use crate::normalize::buildid::read_elf_build_id;
}


#[cfg(feature = "tracing")]
#[macro_use]
#[allow(unused_imports)]
mod log {
    pub(crate) use tracing::debug;
    pub(crate) use tracing::error;
    pub(crate) use tracing::info;
    pub(crate) use tracing::instrument;
    pub(crate) use tracing::trace;
    pub(crate) use tracing::warn;
}

#[cfg(not(feature = "tracing"))]
#[macro_use]
#[allow(unused_imports)]
mod log {
    macro_rules! debug {
        ($($args:tt)*) => {{
          if false {
            // Make sure to use `args` to prevent any warnings about
            // unused variables.
            let _args = format_args!($($args)*);
          }
        }};
    }
    pub(crate) use debug;
    pub(crate) use debug as error;
    pub(crate) use debug as info;
    pub(crate) use debug as trace;
    pub(crate) use debug as warn;
}

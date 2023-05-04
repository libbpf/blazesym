//! **blazesym** is a library that can be used to symbolize addresses. Address
//! symbolization is a common problem in tracing contexts, for example, where users
//! want to reason about functions by name, but low level components report only the
//! "raw" addresses (e.g., in the form of stacktraces).
//!
//! In addition to symbolization, **blazesym** also provides APIs for the reverse
//! operation: looking up addresses from symbol names. That can be useful, for
//! example, for configuring breakpoints or tracepoints.
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
//! [`c_api`] module (note that Rust code should not have to consume these
//! functions and on the ABI level this module organization has no relevance for
//! C).

#![allow(clippy::collapsible_if, clippy::let_and_return, clippy::let_unit_value)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(not(feature = "lru"), allow(dead_code))]

#[cfg(feature = "nightly")]
extern crate test;

pub mod c_api;
mod dwarf;
mod elf;
mod gsym;
pub mod inspect;
mod kernel;
mod ksym;
mod maps;
mod mmap;
pub mod normalize;
mod resolver;
pub mod symbolize;
mod util;
// TODO: Remove `allow`.
#[allow(unused)]
mod zip;

use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::num::NonZeroU32;

use resolver::SymResolver;


// We import all C API items during doc creation to not have to mention the
// `c_api` module in, say, the README.
#[cfg(doc)]
use c_api::*;


/// A type representing addresses.
pub type Addr = usize;


/// An enumeration identifying a process.
#[derive(Clone, Copy, Debug)]
pub enum Pid {
    /// The current process.
    Slf,
    /// The process identified by the provided ID.
    Pid(NonZeroU32),
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


#[cfg(feature = "log")]
#[macro_use]
mod log {
    #[allow(unused)]
    pub(crate) use log::debug;
    pub(crate) use log::error;
    #[allow(unused)]
    pub(crate) use log::info;
    #[allow(unused)]
    pub(crate) use log::trace;
    pub(crate) use log::warn;
}
#[cfg(not(feature = "log"))]
#[macro_use]
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
    #[allow(unused)]
    pub(crate) use debug;
    pub(crate) use debug as error;
    #[allow(unused)]
    pub(crate) use debug as info;
    #[allow(unused)]
    pub(crate) use debug as trace;
    pub(crate) use debug as warn;
}

// A library symbolizes addresses to symbols, filenames, and line numbers.
//
// BlazeSym is a library to symbolize addresses to get symbol names, file
// names of source files, and line numbers.  It can translate a stack
// trace to function names and their locations in the
// source code.
#![doc = include_str!("../README.md")]
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
mod symbolize;
mod util;
// TODO: Remove `allow`.
#[allow(unused)]
mod zip;

use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::num::NonZeroU32;
use std::path::PathBuf;

use resolver::SymResolver;
pub use symbolize::cfg;
pub use symbolize::BlazeSymbolizer;
pub use symbolize::SymbolSrcCfg;
pub use symbolize::SymbolizedResult;
pub use symbolize::SymbolizerFeature;

// We import all C API items during doc creation to not have to mention the
// `c_api` module in, say, the README.
#[cfg(doc)]
use c_api::*;

pub type Addr = usize;


/// An enumeration identifying a process.
#[derive(Clone, Copy, Debug)]
pub enum Pid {
    Slf,
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


/// The context of an address finding request.
///
/// This type passes additional parameters to resolvers.
#[derive(Debug, Default)]
pub(crate) struct FindAddrOpts {
    /// Return the offset of the symbol from the first byte of the
    /// object file if it is true. (False by default)
    pub offset_in_file: bool,
    /// Return the name of the object file if it is true. (False by default)
    pub obj_file_name: bool,
    /// Return the symbol(s) matching a given type. Unknown, by default,
    /// means all types.
    pub sym_type: SymbolType,
}


/// Types of symbols.
#[derive(Clone, Copy, Debug, Default)]
pub enum SymbolType {
    #[default]
    Unknown,
    Function,
    Variable,
}


/// Information of a symbol.
#[derive(Debug)]
pub struct SymbolInfo {
    /// The name of the symbol; for example, a function name.
    pub name: String,
    /// Start address (the first byte) of the symbol
    pub address: Addr,
    /// The size of the symbol. The size of a function for example.
    pub size: usize,
    /// A function or a variable.
    pub sym_type: SymbolType,
    /// The offset in the object file.
    pub file_offset: u64,
    /// The file name of the shared object.
    pub obj_file_name: Option<PathBuf>,
}


#[cfg(feature = "log")]
#[macro_use]
mod log {
    pub use log::debug;
    pub use log::error;
    pub use log::info;
    pub use log::trace;
    pub use log::warn;
}
#[cfg(not(feature = "log"))]
#[macro_use]
mod log {
    #[macro_export]
    macro_rules! debug {
        ($($args:tt)*) => {{
          if false {
            // Make sure to use `args` to prevent any warnings about
            // unused variables.
            let _args = format_args!($($args)*);
          }
        }};
    }
    pub use debug;
    pub use debug as error;
    pub use debug as info;
    pub use debug as trace;
    pub use debug as warn;
}

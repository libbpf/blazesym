// A library symbolizes addresses to symbols, filenames, and line numbers.
//
// BlazeSym is a library to symbolize addresses to get symbol names, file
// names of source files, and line numbers.  It can translate a stack
// trace to function names and their locations in the
// source code.
#![doc = include_str!("../README.md")]
#![allow(
    clippy::collapsible_if,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::module_inception
)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(not(feature = "symbolize"), allow(dead_code))]

#[cfg(feature = "nightly")]
extern crate test;

pub mod c_api;
#[cfg(feature = "symbolize")]
mod dwarf;
mod elf;
#[cfg(feature = "symbolize")]
mod gsym;
#[cfg(feature = "symbolize")]
mod kernel;
#[cfg(feature = "symbolize")]
mod ksym;
mod maps;
mod mmap;
pub mod normalize;
#[cfg(feature = "symbolize")]
mod resolver;
#[cfg(feature = "symbolize")]
mod symbolize;
mod util;
// TODO: Remove `allow`.
#[allow(unused)]
mod zip;

use std::path::PathBuf;

#[cfg(feature = "symbolize")]
use resolver::SymResolver;
#[cfg(feature = "symbolize")]
pub use symbolize::cfg;
#[cfg(feature = "symbolize")]
pub use symbolize::BlazeSymbolizer;
#[cfg(feature = "symbolize")]
pub use symbolize::FindAddrFeature;
#[cfg(feature = "symbolize")]
pub use symbolize::SymbolSrcCfg;
#[cfg(feature = "symbolize")]
pub use symbolize::SymbolizedResult;
#[cfg(feature = "symbolize")]
pub use symbolize::SymbolizerFeature;

// We import all C API items during doc creation to not have to mention the
// `c_api` module in, say, the README.
#[cfg(doc)]
use c_api::*;

pub type Addr = usize;


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

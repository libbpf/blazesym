//! **blazesym** is a library that can be used to symbolize addresses. Address
//! symbolization is a common problem in tracing contexts, for example, where users
//! want to reason about functions by name, but low level components report only the
//! "raw" addresses (e.g., in the form of stacktraces).
//!
//! In addition to symbolization, **blazesym** also provides APIs for the reverse
//! operation: looking up addresses from symbol names. That can be useful, for
//! example, for configuring breakpoints or tracepoints.
//!
//! Here an example illustrating usage of the symbolization functionality:
//! ```no_run
//! use blazesym::symbolize::cfg;
//! use blazesym::Addr;
//! use blazesym::symbolize::Symbolizer;
//! use blazesym::symbolize::SymbolSrcCfg;
//! use blazesym::symbolize::SymbolizedResult;
//!
//! let process_id: u32 = std::process::id(); // <some process id>
//! // Load all symbols of loaded files of the given process.
//! let cfg = SymbolSrcCfg::Process(cfg::Process { pid: process_id.into() });
//! let symbolizer = Symbolizer::new().unwrap();
//!
//! let stack: [Addr; 2] = [0xff023, 0x17ff93b];  // Addresses of instructions
//! let symlist = symbolizer.symbolize(&cfg,      // Pass this configuration every time
//!                                    &stack).unwrap();
//! for i in 0..stack.len() {
//!   let addr = stack[i];
//!
//!   if symlist.len() <= i || symlist[i].len() == 0 {  // Unknown address
//!     println!("0x{addr:016x}");
//!     continue;
//!   }
//!
//!   let sym_results = &symlist[i];
//!   if sym_results.len() > 1 {
//!     // One address may get several results (e.g., when defined in multiple
//!     // compilation units)
//!     println!("0x{addr:016x} ({} entries)", sym_results.len());
//!
//!     for result in sym_results {
//!       let SymbolizedResult {symbol, addr, path, line, column} = result;
//!       println!("    {symbol}@0x{addr:016x} {}:{line}", path.display());
//!     }
//!   } else {
//!     let SymbolizedResult {symbol, addr, path, line, column} = &sym_results[0];
//!     println!("0x{addr:016x} {symbol}@0x{addr:016x} {}:{line}", path.display());
//!   }
//! }
//! ```

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
use std::path::PathBuf;

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

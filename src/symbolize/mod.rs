//! Functionality for symbolizing addresses.
//!
//! This module contains functionality for symbolizing addresses, i.e., finding
//! symbol names and other information based on "raw" addresses.
//!
//! Here an example illustrating usage of the symbolization functionality:
//! ```no_run
//! use blazesym::Addr;
//! use blazesym::symbolize::Symbolizer;
//! use blazesym::symbolize::Source;
//! use blazesym::symbolize::Process;
//! use blazesym::symbolize::SymbolizedResult;
//!
//! let process_id: u32 = std::process::id(); // <some process id>
//! // Load all symbols of loaded files of the given process.
//! let src = Source::Process(Process::new(process_id.into()));
//! let symbolizer = Symbolizer::new();
//!
//! let stack: [Addr; 2] = [0xff023, 0x17ff93b];  // Addresses of instructions
//! let symlist = symbolizer.symbolize(&src,      // Pass this configuration every time
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
//!     // One address may get several results.
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

mod source;
mod symbolizer;

use std::path::PathBuf;

pub use source::Elf;
pub use source::Gsym;
pub use source::Kernel;
pub use source::Process;
pub use source::Source;
pub use symbolizer::Builder;
pub use symbolizer::SymbolizedResult;
pub use symbolizer::Symbolizer;


pub(crate) struct AddrLineInfo {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
}

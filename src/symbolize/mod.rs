//! Functionality for symbolizing addresses.
//!
//! This module contains functionality for symbolizing addresses, i.e., finding
//! symbol names and other information based on "raw" addresses.
//!
//! For example, here we symbolize the backtrace captured via `libc`'s
//! `backtrace` function:
//! ```no_run
//! # use std::cmp::min;
//! # use std::mem::size_of;
//! # use std::mem::transmute;
//! # use std::path::PathBuf;
//! # use std::ptr;
//! use blazesym::symbolize::Source;
//! use blazesym::symbolize::Process;
//! use blazesym::symbolize::Sym;
//! use blazesym::symbolize::Symbolizer;
//! use blazesym::Addr;
//! use blazesym::Pid;
//!
//! # assert_eq!(size_of::<*mut libc::c_void>(), size_of::<Addr>());
//! // Retrieve up to 64 stack frames of the calling thread.
//! const MAX_CNT: usize = 64;
//!
//! let mut addrs_buf = [ptr::null_mut::<libc::c_void>(); MAX_CNT];
//! let addr_cnt = unsafe { libc::backtrace(addrs_buf.as_mut_ptr(), MAX_CNT as _) } as usize;
//! let addrs = &addrs_buf[0..min(addr_cnt, MAX_CNT)];
//! # let addrs = unsafe { transmute::<&[*mut libc::c_void], &[Addr]>(addrs) };
//!
//! // Symbolize the addresses for the current process, as that's where
//! // they were captured.
//! let src = Source::Process(Process::new(Pid::Slf));
//! let symbolizer = Symbolizer::new();
//! let syms = symbolizer.symbolize(&src, addrs).unwrap();
//!
//! let addr_width = 16;
//! let mut prev_addr_idx = None;
//!
//! for (sym, addr_idx) in syms {
//!     if let Some(idx) = prev_addr_idx {
//!         // Print a line for all addresses that did not get symbolized.
//!         for input_addr in addrs.iter().take(addr_idx).skip(idx + 1) {
//!             println!("{input_addr:#0width$x}: <no-symbol>", width = addr_width)
//!         }
//!     }
//!
//!     let Sym {
//!         name,
//!         addr,
//!         offset,
//!         line,
//!         column,
//!         ..
//!     } = &sym;
//!
//!     let src_loc = if let (Some(path), Some(line)) = (sym.to_path(), line) {
//!         if let Some(col) = column {
//!             format!(" {}:{line}:{col}", path.display())
//!         } else {
//!             format!(" {}:{line}", path.display())
//!         }
//!     } else {
//!         String::new()
//!     };
//!
//!     if prev_addr_idx != Some(addr_idx) {
//!         // If the address index changed we reached a new symbol.
//!         println!(
//!             "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{src_loc}",
//!             input_addr = addrs[addr_idx],
//!             width = addr_width
//!         );
//!     } else {
//!         // Otherwise we are dealing with an inlined call.
//!         println!(
//!             "{:width$}  {name} @ {addr:#x}+{offset:#x}{src_loc}",
//!             " ",
//!             width = addr_width
//!         );
//!     }
//!
//!     prev_addr_idx = Some(addr_idx);
//! }
//! ```

mod source;
mod symbolizer;

use std::ffi::OsStr;
use std::path::Path;

pub use source::Elf;
pub use source::Gsym;
pub use source::GsymData;
pub use source::GsymFile;
pub use source::Kernel;
pub use source::Process;
pub use source::Source;
pub use symbolizer::Builder;
pub use symbolizer::Sym;
pub use symbolizer::Symbolizer;


pub(crate) struct AddrCodeInfo<'src> {
    pub dir: &'src Path,
    pub file: &'src OsStr,
    pub line: Option<u32>,
    pub column: Option<u16>,
}

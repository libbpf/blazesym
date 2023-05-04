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

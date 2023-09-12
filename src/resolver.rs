use std::fmt::Debug;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::symbolize::AddrSrcInfo;
use crate::Addr;
use crate::Result;


/// The source code language from which a symbol originates.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) enum SrcLang {
    /// The language is unknown.
    #[default]
    Unknown,
    /// The language is C++.
    Cpp,
    /// The language is Rust.
    Rust,
}


/// Our internal representation of a symbol.
pub(crate) struct IntSym<'src> {
    /// The name of the symbol.
    pub(crate) name: &'src str,
    /// The symbol's normalized address.
    pub(crate) addr: Addr,
    /// The source code language from which the symbol originates.
    pub(crate) lang: SrcLang,
}


/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e.g., a symbol file.
pub(crate) trait SymResolver
where
    Self: Debug,
{
    /// Find the names and the start addresses of a symbol found for
    /// the given address.
    fn find_syms(&self, addr: Addr) -> Result<Vec<IntSym<'_>>>;
    /// Find the address and size of a symbol name.
    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo>>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: Addr) -> Result<Option<AddrSrcInfo>>;
    /// Translate an address (virtual) in a process to the file offset
    /// in the object file.
    fn addr_file_off(&self, addr: Addr) -> Option<u64>;
}

use std::fmt::Debug;
use std::path::Path;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::symbolize::AddrLineInfo;
use crate::Addr;


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
    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)>;
    /// Find the address and size of a symbol name.
    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymInfo>>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: Addr) -> Option<AddrLineInfo>;
    /// Translate an address (virtual) in a process to the file offset
    /// in the object file.
    fn addr_file_off(&self, addr: Addr) -> Option<u64>;
    /// Get the file name of the shared object.
    fn get_obj_file_name(&self) -> &Path;
}

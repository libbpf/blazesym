use std::fmt::Debug;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::symbolize::AddrCodeInfo;
use crate::symbolize::IntSym;
use crate::symbolize::Reason;
use crate::Addr;
use crate::Result;


/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e.g., a symbol file.
pub(crate) trait SymResolver
where
    Self: Debug,
{
    /// Find the symbol corresponding to the given address.
    fn find_sym(&self, addr: Addr) -> Result<Result<IntSym<'_>, Reason>>;
    /// Find information about a symbol given its name.
    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'_>>>;
    /// Finds the source code location for a given address.
    ///
    /// This function tries to find source code information for the given
    /// address. If no such information was found, `None` will be returned. If
    /// `inlined_fns` is true, information about inlined calls at the very
    /// address will also be looked up and reported as the optional
    /// [`AddrCodeInfo::inlined`] attribute.
    fn find_code_info(&self, addr: Addr, inlined_fns: bool) -> Result<Option<AddrCodeInfo<'_>>>;
}

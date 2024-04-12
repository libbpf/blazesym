use std::fmt::Debug;

use crate::symbolize::FindSymOpts;
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
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<IntSym<'_>, Reason>>;
}

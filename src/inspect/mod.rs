//! Functionality for inspecting files such as ELF or Gsym. Supported
//! operations are looking up symbol information (address, size, type,
//! etc.) by name or iterating over all available symbols.
//!
//! ```no_run
//! use blazesym::inspect::source::Elf;
//! use blazesym::inspect::source::Source;
//! use blazesym::inspect::Inspector;
//!
//! let src = Source::Elf(Elf::new("/usr/bin/libc.so"));
//! let inspector = Inspector::new();
//! let results = inspector
//!     .lookup(&src, &["fopen"])
//!     .unwrap();
//!
//! // `results` contains a list of addresses of `fopen` symbols in `libc`.
//! // There probably will only be a single one.
//! ```

#[cfg_attr(not(feature = "dwarf"), allow(unused_variables))]
mod inspector;
pub mod source;

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::ops::ControlFlow;

use crate::Addr;
use crate::Result;
use crate::SymType;

pub use inspector::Inspector;


/// Information about a symbol.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SymInfo<'src> {
    /// The name of the symbol; for example, a function name.
    pub name: Cow<'src, str>,
    /// Start address (the first byte) of the symbol.
    pub addr: Addr,
    /// The size of the symbol.
    ///
    /// Note that some symbolization sources report a size of `0` to
    /// mean *either* that the symbol's size is actually `0` or that it
    /// has an unknown size. Given that the library has way to
    /// differentiate, a value of `Some(0)` will be reported in such
    /// ambiguous cases.
    pub size: Option<usize>,
    /// A function or a variable.
    pub sym_type: SymType,
    /// The offset in the object file.
    pub file_offset: Option<u64>,
    /// The path to or name of the module containing the symbol.
    pub module: Option<Cow<'src, OsStr>>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl SymInfo<'_> {
    /// Clone the object ensuring that references are converted to owned
    /// objects.
    #[inline]
    pub fn to_owned(&self) -> SymInfo<'static> {
        SymInfo {
            name: Cow::Owned(self.name.to_string()),
            addr: self.addr,
            size: self.size,
            sym_type: self.sym_type,
            file_offset: self.file_offset,
            module: self
                .module
                .as_deref()
                .map(|path| Cow::Owned(path.to_os_string())),
            _non_exhaustive: (),
        }
    }
}


/// The context of an address finding request.
///
/// This type passes additional parameters to resolvers.
#[derive(Debug, Default)]
pub(crate) struct FindAddrOpts {
    /// Whether or not to return file offsets by attempting to populate
    /// the [`SymInfo::file_offset`] attribute.
    ///
    /// This options default to `false`.
    pub file_offset: bool,
    /// Return the symbol(s) matching a given type.
    ///
    /// [`Undefined`][SymType::Undefined] indicates that all supported
    /// symbols are of interest.
    pub sym_type: SymType,
}


/// The signature of a function for iterating over symbols.
pub(crate) type ForEachFn<'f> = dyn FnMut(&SymInfo<'_>) -> ControlFlow<()> + 'f;


/// The trait providing inspection functionality.
pub(crate) trait Inspect
where
    Self: Debug,
{
    /// Find information about a symbol given its name.
    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'_>>>;

    /// Perform an operation on each symbol.
    fn for_each(&self, opts: &FindAddrOpts, f: &mut ForEachFn<'_>) -> Result<()>;
}

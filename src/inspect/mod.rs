//! Functionality for inspecting files such as ELF or Gsym.
//!
//! ```no_run
//! use blazesym::inspect;
//! use blazesym::inspect::Inspector;
//!
//! let src = inspect::Source::Elf(inspect::Elf::new("/usr/bin/libc.so"));
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
mod source;

use std::borrow::Cow;
use std::path::Path;

use crate::Addr;
use crate::SymType;

pub use inspector::Inspector;
#[cfg(feature = "breakpad")]
pub use source::Breakpad;
pub use source::Elf;
pub use source::Source;


/// Information about a symbol.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SymInfo<'src> {
    /// The name of the symbol; for example, a function name.
    pub name: Cow<'src, str>,
    /// Start address (the first byte) of the symbol.
    pub addr: Addr,
    /// The size of the symbol. The size of a function for example.
    pub size: usize,
    /// A function or a variable.
    pub sym_type: SymType,
    /// The offset in the object file.
    pub file_offset: Option<u64>,
    /// The file name of the shared object.
    pub obj_file_name: Option<Cow<'src, Path>>,
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
            obj_file_name: self
                .obj_file_name
                .as_deref()
                .map(|path| Cow::Owned(path.to_path_buf())),
        }
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
    /// Return the symbol(s) matching a given type.
    /// [`Undefined`][SymType::Undefined] indicates that all supported
    /// symbols are of interest.
    pub sym_type: SymType,
}

use std::path::PathBuf;


/// A GNU build ID, as raw bytes.
type BuildId = Vec<u8>;


/// Meta information about an ELF file (executable, shared object, ...).
#[derive(Clone, Debug, PartialEq)]
pub struct Elf {
    /// The canonical absolute path to the ELF file, including its name.
    pub path: PathBuf,
    /// The ELF file's build ID, if available.
    pub build_id: Option<BuildId>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}


/// Meta information about an address that could not be determined to be
/// belonging to a specific component. Such an address will be reported
/// in non-normalized form (as provided by the user).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Unknown {
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl From<Unknown> for UserAddrMeta {
    fn from(unknown: Unknown) -> Self {
        Self::Unknown(unknown)
    }
}


/// Meta information for an address.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum UserAddrMeta {
    Elf(Elf),
    Unknown(Unknown),
}

impl UserAddrMeta {
    /// Retrieve the [`Elf`] of this enum, if this variant is active.
    pub fn elf(&self) -> Option<&Elf> {
        match self {
            Self::Elf(elf) => Some(elf),
            _ => None,
        }
    }
}

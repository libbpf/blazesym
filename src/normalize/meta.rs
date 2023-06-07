use std::path::PathBuf;


/// A GNU build ID, as raw bytes.
type BuildId = Vec<u8>;


/// Meta information about an ELF file inside an APK.
#[derive(Clone, Debug, PartialEq)]
pub struct ApkElf {
    /// The canonical absolute path to the APK, including its name.
    pub apk_path: PathBuf,
    /// The relative path to the ELF file inside the APK.
    pub elf_path: PathBuf,
    /// The ELF file's build ID, if available.
    pub elf_build_id: Option<BuildId>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}


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
    ApkElf(ApkElf),
    Elf(Elf),
    Unknown(Unknown),
}

impl UserAddrMeta {
    /// Retrieve the [`ApkElf`] of this enum, if this variant is active.
    pub fn apk_elf(&self) -> Option<&ApkElf> {
        match self {
            Self::ApkElf(entry) => Some(entry),
            _ => None,
        }
    }

    /// Retrieve the [`Elf`] of this enum, if this variant is active.
    pub fn elf(&self) -> Option<&Elf> {
        match self {
            Self::Elf(elf) => Some(elf),
            _ => None,
        }
    }

    /// Retrieve the [`Unknown`] of this enum, if this variant is active.
    pub fn unknown(&self) -> Option<&Unknown> {
        match self {
            Self::Unknown(unknown) => Some(unknown),
            _ => None,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can access individual variants of a
    /// [`UserAddrMeta`] via the accessor functions.
    #[test]
    fn user_addr_meta_accessors() {
        let meta = UserAddrMeta::ApkElf(ApkElf {
            apk_path: PathBuf::from("/tmp/archive.apk"),
            elf_path: PathBuf::from("object.so"),
            elf_build_id: None,
            _non_exhaustive: (),
        });
        assert!(meta.apk_elf().is_some());
        assert!(meta.elf().is_none());
        assert!(meta.unknown().is_none());

        let meta = UserAddrMeta::Elf(Elf {
            path: PathBuf::from("/tmp/executable.bin"),
            build_id: None,
            _non_exhaustive: (),
        });
        assert!(meta.apk_elf().is_none());
        assert!(meta.elf().is_some());
        assert!(meta.unknown().is_none());

        let meta = UserAddrMeta::Unknown(Unknown {
            _non_exhaustive: (),
        });
        assert!(meta.apk_elf().is_none());
        assert!(meta.elf().is_none());
        assert!(meta.unknown().is_some());
    }
}

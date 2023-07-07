use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::path::Path;

use crate::elf;
use crate::elf::types::Elf64_Nhdr;
use crate::elf::ElfParser;
use crate::log::warn;
use crate::util::ReadRaw as _;


/// Typedefs for functions reading build IDs.
pub(crate) type BuildIdFn = dyn Fn(&Path) -> Result<Option<Vec<u8>>>;
pub(crate) type ElfBuildIdFn = dyn Fn(&ElfParser) -> Result<Option<Vec<u8>>>;


/// A type representing a build ID note.
///
/// In the ELF file, this header is typically followed by the variable sized
/// build ID.
#[repr(C)]
struct BuildIdNote {
    /// ELF note header.
    header: Elf64_Nhdr,
    /// NUL terminated string representing the name.
    name: [u8; 4],
}

// SAFETY: `BuildIdNote` is valid for any bit pattern.
unsafe impl crate::util::Pod for BuildIdNote {}

/// Iterate over all note sections to find one of type
/// [`NT_GNU_BUILD_ID`][elf::types::NT_GNU_BUILD_ID].
fn read_build_id_from_notes(parser: &ElfParser) -> Result<Option<Vec<u8>>> {
    let shdrs = parser.section_headers()?;
    for (idx, shdr) in shdrs.iter().enumerate() {
        if shdr.sh_type == elf::types::SHT_NOTE {
            // SANITY: We just found the index so the section data should always
            //         be found.
            let mut bytes = parser.section_data(idx).unwrap();
            let header = bytes.read_pod_ref::<BuildIdNote>().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "failed to read build ID section header",
                )
            })?;
            if header.header.n_type == elf::types::NT_GNU_BUILD_ID {
                let build_id = bytes.to_vec();
                return Ok(Some(build_id))
            }
        }
    }
    Ok(None)
}

/// Attempt to read an ELF binary's build ID from the .note.gnu.build-id section.
fn read_build_id_from_section_name(parser: &ElfParser) -> Result<Option<Vec<u8>>> {
    let build_id_section = ".note.gnu.build-id";
    // The build ID is contained in the `.note.gnu.build-id` section. See
    // elf(5).
    if let Ok(Some(idx)) = parser.find_section(build_id_section) {
        // SANITY: We just found the index so the section should always be
        //         found.
        let shdr = parser.section_headers()?.get(idx).unwrap();
        if shdr.sh_type != elf::types::SHT_NOTE {
            warn!(
                "build ID section {build_id_section} is of unsupported type ({})",
                shdr.sh_type
            );
            return Ok(None)
        }

        // SANITY: We just found the index so the section should always be
        //         found.
        let mut bytes = parser.section_data(idx).unwrap();
        let header = bytes.read_pod_ref::<BuildIdNote>().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "failed to read build ID section header",
            )
        })?;
        if &header.name != b"GNU\0" {
            warn!(
                "encountered unsupported build ID type {:?}; ignoring",
                header.name
            );
            Ok(None)
        } else {
            // Every byte following the header is part of the build ID.
            let build_id = bytes.to_vec();
            Ok(Some(build_id))
        }
    } else {
        Ok(None)
    }
}

pub(super) trait BuildIdReader: 'static {
    fn read_build_id_from_elf(path: &Path) -> Result<Option<Vec<u8>>>;
    fn read_build_id(parser: &ElfParser) -> Result<Option<Vec<u8>>>;
}


pub(super) struct DefaultBuildIdReader;

impl BuildIdReader for DefaultBuildIdReader {
    /// Attempt to read an ELF binary's build ID.
    #[cfg_attr(feature = "tracing", crate::log::instrument)]
    fn read_build_id(parser: &ElfParser) -> Result<Option<Vec<u8>>> {
        if let Some(build_id) = read_build_id_from_section_name(parser)? {
            Ok(Some(build_id))
        } else if let Some(build_id) = read_build_id_from_notes(parser)? {
            Ok(Some(build_id))
        } else {
            Ok(None)
        }
    }

    /// Attempt to read an ELF binary's build ID from a file.
    #[cfg_attr(feature = "tracing", crate::log::instrument)]
    fn read_build_id_from_elf(path: &Path) -> Result<Option<Vec<u8>>> {
        let file = File::open(path)?;
        let parser = ElfParser::open_file(file)?;
        Self::read_build_id(&parser)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Check that we can read a binary's build ID based on the ELF section name as well as ELF section type.
    #[test]
    fn build_id_reading_from_name_and_notes() {
        fn test(f: fn(&ElfParser) -> Result<Option<Vec<u8>>>) {
            let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("libtest-so.so");

            let file = File::open(elf).unwrap();
            let parser = ElfParser::open_file(file).unwrap();
            let build_id = f(&parser).unwrap().unwrap();
            // The file contains a sha1 build ID, which is always 40 hex digits.
            assert_eq!(build_id.len(), 20, "'{build_id:?}'");
        }

        test(read_build_id_from_section_name);
        test(read_build_id_from_notes);
    }

    /// Check that we can read a binary's build ID.
    #[test]
    fn build_id_reading() {
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");

        let build_id = DefaultBuildIdReader::read_build_id_from_elf(&elf)
            .unwrap()
            .unwrap();
        // The file contains a sha1 build ID, which is always 40 hex digits.
        assert_eq!(build_id.len(), 20, "'{build_id:?}'");

        // The shared object is explicitly built without build ID.
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");
        let build_id = DefaultBuildIdReader::read_build_id_from_elf(&elf).unwrap();
        assert_eq!(build_id, None);
    }
}

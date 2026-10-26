//! Support for reading of GNU .`debug_sup` data as prescribed in DWARF v5;
//! .`debug_sup` replaces .`gnu_debugaltlink` in the current standard and
//! plays the same role: it functions as a pointer to a
//! supplementary object file.
//!
//! .`debug_sup` is a special section of executable files that should contain:
//!   - `version`: u16 representing the version of the DWARF information for the
//!     compilation unit
//!   - `is_supplementary`: u8 which is set to 1 if the file in which the
//!     section is stored is a supplementary file, 0 o.w.
//!   - `sup_filename`: null-terminated supplementary file name or path (is
//!     !`is_supplementary`)
//!   - `sup_checksum_len`: uleb128 indicating the length of the following
//!     checksum field
//!   - `sup_checksum`: [u8: `sup_checksum_len`] unique supplementary file id

use std::path::Path;

use crate::elf::ElfParser;
use crate::error::Error;
use crate::error::ErrorExt as _;
use crate::error::IntoError as _;
use crate::util::bytes_to_path;
use crate::util::ReadRaw as _;
use crate::Result;


#[derive(Debug)]
pub(crate) struct DebugSupInfo<'dwarf> {
    pub _version: u16,
    pub is_supplementary: bool,
    pub path: Option<&'dwarf Path>,
    pub checksum: &'dwarf [u8],
}


/// Read the debug sup section.
pub(crate) fn read_debug_sup(parser: &ElfParser) -> Result<Option<DebugSupInfo<'_>>> {
    let debug_sup_section = ".debug_sup";
    let idx = if let Ok(Some(idx)) = parser.find_section(debug_sup_section) {
        idx
    } else {
        return Ok(None)
    };

    let data = parser
        .section_data(idx)
        .with_context(|| format!("failed to read {debug_sup_section} section data"))?;
    parse_debug_sup_section_data(data)
}


fn parse_debug_sup_section_data(mut data: &[u8]) -> Result<Option<DebugSupInfo<'_>>> {
    let version = data
        .read_u16()
        .ok_or_invalid_data(|| "failed to read .debug_sup version")?;

    let is_supplementary = match data
        .read_u8()
        .ok_or_invalid_data(|| "failed to read .debug_sup is_supplementary")?
    {
        0 => false,
        1 => true,
        v => {
            return Err(Error::with_invalid_data(format!(
                "invalid is_supplementary field value: {v}"
            )))
        }
    };

    let path_string = data
        .read_cstr()
        .ok_or_invalid_data(|| "failed to read .debug_sup file field")?;
    let path = if !is_supplementary {
        if path_string.is_empty() {
            return Err(Error::with_invalid_data("debug sup target is empty"))
        }
        bytes_to_path(path_string.to_bytes()).ok()
    } else {
        if !path_string.is_empty() {
            return Err(Error::with_invalid_data(
                "debug sup target is not empty in a supplementary file",
            ))
        }
        None
    };

    let sup_checksum_len = data
        .read_u64_leb128()
        .ok_or_invalid_data(|| "failed to read .debug_sup sup_checksum_len")?;
    let checksum = data
        .read_slice(sup_checksum_len.try_into().unwrap())
        .ok_or_invalid_data(|| "failed to read .debug_sup checksum")?;

    let sup = DebugSupInfo {
        _version: version,
        is_supplementary,
        path,
        checksum,
    };
    Ok(Some(sup))
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::size_of_val;
    use std::slice;

    use test_tag::tag;

    use crate::test_helper::corrupt_elf_section;
    use crate::ErrorKind;


    /// Check that we can correctly read the checksum from a `.debug_sup`
    /// section data.
    #[tag(miri)]
    #[test]
    fn unaligned_debug_sup_parsing() {
        let section_data = [
            0x5, 0x0, 0x0, b'.', b'.', b'/', b'.', b'.', b'/', b'.', b'd', b'w', b'z', b'/', b'p',
            b'r', b'o', b'g', b'r', b'a', b'm', 0x0, 0x14, 0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98,
            0xa1, 0xcc, 0x3f, 0x90, 0x45, 0x69, 0x9a, 0xda, 0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8,
        ];

        let mut buffer = [0u64; 8];
        let buffer = unsafe {
            slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<u8>(),
                buffer.len() * size_of_val(&buffer[0]),
            )
        };

        // Make the buffer unaligned.
        let buffer = &mut buffer[3..3 + section_data.len()];
        // Now write the section data into it.
        let () = buffer.copy_from_slice(&section_data);

        let DebugSupInfo {
            _version: version,
            is_supplementary,
            path,
            checksum,
        } = parse_debug_sup_section_data(buffer).unwrap().unwrap();

        assert_eq!(version, 5);
        assert!(!is_supplementary);
        assert!(path.is_some());
        assert_eq!(path.unwrap(), Path::new("../../.dwz/program"));
        assert_eq!(
            checksum,
            [
                0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98, 0xa1, 0xcc, 0x3f, 0x90, 0x45, 0x69, 0x9a, 0xda,
                0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8
            ]
        );
    }

    /// Check that we handle empty version in `.debug_sup` section.
    #[tag(miri)]
    #[test]
    fn empty_version_debug_sup_parsing() {
        let section_data = &[];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("version"));
    }

    /// Check that we handle no `is_supplementary` in debug sup section.
    #[tag(miri)]
    #[test]
    fn no_is_supplementary_debug_sup_parsing() {
        let section_data = &[0x5, 0x0];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to read .debug_sup is_supplementary"));
    }

    /// Check that we handle invalid `is_supplementary` in debug sup section.
    #[tag(miri)]
    #[test]
    fn invalid_is_supplementary_debug_sup_parsing() {
        let section_data = &[0x5, 0x0, 0x2];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("invalid is_supplementary"));
    }

    /// Check that we handle no path in debug sup section.
    #[tag(miri)]
    #[test]
    fn no_path_debug_sup_parsing() {
        let section_data = &[0x5, 0x0, 0x0];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("file field"));
    }

    /// Check that we handle empty path in debug sup section.
    #[tag(miri)]
    #[test]
    fn empty_path_debug_sup_parsing() {
        let section_data = &[
            0x5, 0x0, 0x0, 0x0, 0x14, 0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98, 0xa1, 0xcc, 0x3f, 0x90,
            0x45, 0x69, 0x9a, 0xda, 0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8,
        ];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("debug sup target is empty"));
    }

    /// Check that we handle not empty path in debug sup section of
    /// supplementary file.
    #[tag(miri)]
    #[test]
    fn supplementary_not_empty_path_debug_sup_parsing() {
        let section_data = &[
            0x5, 0x0, 0x1, b'.', b'.', b'/', b'.', b'.', b'/', b'.', b'd', b'w', b'z', b'/', b'p',
            b'r', b'o', b'g', b'r', b'a', b'm', 0x0, 0x14, 0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98,
            0xa1, 0xcc, 0x3f, 0x90, 0x45, 0x69, 0x9a, 0xda, 0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8,
        ];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("debug sup target is not empty in a supplementary file"));
    }

    /// Check that we handle empty checksum lenght in debug sup section.
    #[tag(miri)]
    #[test]
    fn empty_checksum_len_debug_sup_parsing() {
        let section_data = &[
            0x5, 0x0, 0x0, b'.', b'.', b'/', b'.', b'.', b'/', b'.', b'd', b'w', b'z', b'/', b'p',
            b'r', b'o', b'g', b'r', b'a', b'm', 0x0,
        ];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("sup_checksum_len"));
    }

    /// Check that we handle empty checksum in debug sup section.
    #[tag(miri)]
    #[test]
    fn empty_checksum_debug_sup_parsing() {
        let section_data = &[
            0x5, 0x0, 0x0, b'.', b'.', b'/', b'.', b'.', b'/', b'.', b'd', b'w', b'z', b'/', b'p',
            b'r', b'o', b'g', b'r', b'a', b'm', 0x0, 0x14,
        ];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }

    /// Check that we handle wrong checksum length in debug sup section.
    #[tag(miri)]
    #[test]
    fn wrong_checksum_len_debug_sup_parsing() {
        let section_data = &[
            0x5, 0x0, 0x0, b'.', b'.', b'/', b'.', b'.', b'/', b'.', b'd', b'w', b'z', b'/', b'p',
            b'r', b'o', b'g', b'r', b'a', b'm', 0x0, 0x20, 0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98,
            0xa1, 0xcc, 0x3f, 0x90, 0x45, 0x69, 0x9a, 0xda, 0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8,
        ];

        let result = parse_debug_sup_section_data(section_data);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }

    /// Check that we can successfully read an ELF file's debug sup section.
    #[test]
    fn debug_link_reading() {
        let dbg = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-dwarf-only-sup.dbg");

        let parser = ElfParser::open(dbg.as_path()).unwrap();
        let DebugSupInfo {
            _version: version,
            is_supplementary,
            path,
            checksum,
        } = read_debug_sup(&parser).unwrap().unwrap();
        assert_eq!(version, 5);
        assert!(!is_supplementary);
        assert!(path.is_some());
        assert_eq!(path.unwrap(), Path::new("test-stable-addrs-dwarf-5.dwz"));

        let dbg = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-dwarf-5.dwz");
        let parser = ElfParser::open(&dbg).unwrap();
        let DebugSupInfo {
            _version: version,
            is_supplementary,
            path,
            checksum: checksum_dwz,
        } = read_debug_sup(&parser).unwrap().unwrap();
        assert_eq!(version, 5);
        assert!(is_supplementary);
        assert!(path.is_none());
        assert_eq!(checksum, checksum_dwz);
    }

    /// Make sure that we report an error instead of panicking when the
    /// `.debug_sup` section's data cannot be read.
    #[test]
    fn unreadable_debug_sup_section_handling() {
        let dbg = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-dwarf-only-sup.dbg");
        let corrupted = corrupt_elf_section(&dbg, ".debug_sup");

        let parser = ElfParser::open(corrupted.path()).unwrap();
        let err = read_debug_sup(&parser).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
    }
}

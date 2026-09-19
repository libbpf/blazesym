//! Support for reading of GNU debug altlink data.
//!
//! From <https://sourceware.org/git/?p=dwz.git;a=blob;f=dwz.c;hb=HEAD>:
//!
//! A debug altlink is a special section of the executable file named
//! `.gnu_debugaltlink`. The section must contain:
//! - A relative path, followed by a zero byte, and
//! - a SHA1 checksum (build-id) of the common file.

use std::borrow::Cow;
use std::path::Path;

use crate::elf::ElfParser;
use crate::error::IntoError as _;
use crate::util::bytes_to_path;
use crate::util::ReadRaw as _;
use crate::BuildId;
use crate::Result;


/// Read the debug altlink.
pub(crate) fn read_debug_altlink(parser: &ElfParser) -> Result<Option<(&Path, BuildId<'_>)>> {
    let debug_altlink_section = ".gnu_debugaltlink";
    let idx = if let Ok(Some(idx)) = parser.find_section(debug_altlink_section) {
        idx
    } else {
        return Ok(None)
    };

    // SANITY: We just found the index so the section should always be
    //         found.
    let data = parser.section_data(idx).unwrap();
    parse_debug_altlink_section_data(data)
}


fn parse_debug_altlink_section_data(mut data: &[u8]) -> Result<Option<(&Path, BuildId<'_>)>> {
    let path = data
        .read_cstr()
        .ok_or_invalid_data(|| "failed to read debug altlink path")?;
    let path = bytes_to_path(path.to_bytes())?;

    let build_id = data
        .read_slice(data.len())
        .ok_or_invalid_data(|| "failed to read debug altlink build ID")?;
    Ok(Some((path, Cow::Borrowed(build_id))))
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::size_of_val;
    use std::slice;

    use test_tag::tag;


    /// Check that we can correctly read a build id from debug altlink section
    /// data.
    #[tag(miri)]
    #[test]
    fn unaligned_debug_altlink_parsing() {
        let section_data = [
            b'.', b'.', b'/', b'.', b'.', b'/', b'.', b'd', b'w', b'z', b'/', b'p', b'r', b'o',
            b'g', b'r', b'a', b'm', 0x0, 0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98, 0xa1, 0xcc, 0x3f,
            0x90, 0x45, 0x69, 0x9a, 0xda, 0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8,
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

        let (path, build_id) = parse_debug_altlink_section_data(buffer).unwrap().unwrap();
        assert_eq!(path, Path::new("../../.dwz/program"));
        assert_eq!(
            build_id.as_ref(),
            [
                0x7f, 0xd3, 0x76, 0x0a, 0xf3, 0x98, 0xa1, 0xcc, 0x3f, 0x90, 0x45, 0x69, 0x9a, 0xda,
                0x29, 0xe0, 0xb6, 0x6b, 0x45, 0xc8
            ]
        );
    }
}

//! Support for reading of GNU debug link data.
//!
//! From <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html>:
//!
//! A debug link is a special section of the executable file named
//! .gnu_debuglink. The section must contain:
//! - A filename, with any leading directory components removed, followed by a
//!   zero byte,
//! - zero to three bytes of padding, as needed to reach the next four-byte
//!   boundary within the section, and
//! - a four-byte CRC checksum, stored in the same endianness used for the
//!   executable file itself. The checksum is computed on the debugging
//!   information file’s full contents by the function given below, passing zero
//!   as the crc argument.

use std::ffi::OsStr;
use std::mem::take;
use std::path::Path;
use std::path::PathBuf;

use crate::elf::ElfParser;
use crate::error::IntoError as _;
use crate::util::bytes_to_os_str;
use crate::util::ReadRaw as _;
use crate::Result;


enum State {
    FixedDir {
        idx: usize,
    },
    CanonicalTarget {
        canonical_linkee: PathBuf,
    },
    DynamicDirs {
        fixed_dir_idx: usize,
        canonical_rel_linkee: PathBuf,
        linkee_dir: PathBuf,
    },
}

pub(crate) struct DebugFileIter<'path> {
    /// The fixed directories to search.
    fixed_dirs: &'path [PathBuf],
    /// The path to the file containing the debug link.
    canonical_linker: Option<&'path Path>,
    /// The debug link target file.
    linkee: &'path OsStr,
    /// The iteration state.
    state: State,
}

impl<'path> DebugFileIter<'path> {
    pub(crate) fn new(
        fixed_dirs: &'path [PathBuf],
        canonical_linker: Option<&'path Path>,
        linkee: &'path OsStr,
    ) -> Self {
        Self {
            fixed_dirs,
            canonical_linker,
            linkee,
            state: State::FixedDir { idx: 0 },
        }
    }
}

impl Iterator for DebugFileIter<'_> {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            State::FixedDir { idx } => {
                if let Some(dir) = self.fixed_dirs.get(*idx) {
                    *idx += 1;
                    Some(dir.join(self.linkee))
                } else {
                    // We covered all the "fixed" directories. Move on to the
                    // dynamic stuff, if possible.
                    if let Some(linker) = self.canonical_linker {
                        let mut path = linker.to_path_buf();
                        let () = path.set_file_name(self.linkee);

                        self.state = State::CanonicalTarget {
                            canonical_linkee: path,
                        };
                        return self.next()
                    }
                    None
                }
            }
            State::CanonicalTarget { canonical_linkee } => {
                let path = canonical_linkee.clone();
                let result = take(canonical_linkee);
                let mut components = path.components();
                // Remove the root directory to make the path relative. That
                // allows for joining to work as expected.
                let _ = components.next();
                // Remove the file name, as we will always append it anyway.
                let _ = components.next_back();
                let path = components.as_path();

                self.state = State::DynamicDirs {
                    fixed_dir_idx: 0,
                    canonical_rel_linkee: path.to_path_buf(),
                    linkee_dir: path.to_path_buf(),
                };
                Some(result)
            }
            State::DynamicDirs {
                fixed_dir_idx,
                canonical_rel_linkee,
                linkee_dir,
            } => {
                if let Some(fixed_dir) = self.fixed_dirs.get(*fixed_dir_idx) {
                    let dir = take(linkee_dir);
                    match dir.parent() {
                        Some(parent) if !parent.as_os_str().is_empty() => {
                            *linkee_dir = parent.to_path_buf();
                        }
                        _ => {
                            *linkee_dir = canonical_rel_linkee.to_path_buf();
                            *fixed_dir_idx += 1;
                        }
                    }
                    Some(fixed_dir.join(dir).join(self.linkee))
                } else {
                    None
                }
            }
        }
    }
}


/// Read the debug link.
pub(crate) fn read_debug_link(parser: &ElfParser) -> Result<Option<(&OsStr, u32)>> {
    let debug_link_section = ".gnu_debuglink";
    let idx = if let Ok(Some(idx)) = parser.find_section(debug_link_section) {
        idx
    } else {
        return Ok(None)
    };

    // SANITY: We just found the index so the section should always be
    //         found.
    let data = parser.section_data(idx).unwrap();
    parse_debug_link_section_data(data)
}


fn parse_debug_link_section_data(mut data: &[u8]) -> Result<Option<(&OsStr, u32)>> {
    let data_start = data;
    let file = data
        .read_cstr()
        .ok_or_invalid_data(|| "failed to read debug link file name")?;
    let file = bytes_to_os_str(file.to_bytes())?;

    // TODO: Use `std::ptr::byte_offset_from` once our MSRV is 1.75.
    let cur_offset = data.as_ptr() as usize - data_start.as_ptr() as usize;
    // The offset is aligned to the next four byte boundary relative to
    // the start of the section.
    let align = 4;
    let crc_offset = (cur_offset + (align - 1)) & !(align - 1);
    let () = data
        .advance(crc_offset - cur_offset)
        .ok_or_invalid_data(|| {
            "debug link section contains insufficient data: checksum not found"
        })?;
    // TODO: The CRC value is in the same endianess as the ELF file itself. Once
    //       we support non-host endianesses we need to take that into account.
    let crc = data
        .read_u32()
        .ok_or_invalid_data(|| "failed to read debug link checksum")?;
    Ok(Some((file, crc)))
}


pub(crate) fn debug_link_crc32(data: &[u8]) -> u32 {
    static CRC32_TABLE: [u32; 256] = [
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535,
        0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd,
        0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d,
        0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
        0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
        0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac,
        0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab,
        0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
        0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb,
        0x086d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea,
        0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158, 0x3ab551ce,
        0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
        0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409,
        0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739,
        0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344, 0x8708a3d2, 0x1e01f268,
        0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0,
        0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8,
        0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
        0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703,
        0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7,
        0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
        0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae,
        0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6,
        0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d,
        0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5,
        0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
        0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
    ];

    let crc = 0u32;
    let crc = data.iter().fold(!crc, |crc, byte| {
        let idx = (crc ^ u32::from(*byte)) & 0xff;
        CRC32_TABLE[idx as usize] ^ (crc >> 8)
    });

    !crc
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::size_of_val;
    use std::path::Path;
    use std::slice;

    use test_tag::tag;

    use crate::elf::DEFAULT_DEBUG_DIRS;
    use crate::mmap::Mmap;


    /// Check that we can correctly read a CRC checksum from aligned
    /// debug link section data.
    #[tag(miri)]
    #[test]
    fn unaligned_debug_link_parsing() {
        let section_data = [
            b'p', b'r', b'o', b'g', b'r', b'a', b'm', b'.', b'd', b'e', b'b', b'u', b'g', 0x0, 0x0,
            0x0, 0x69, 0xc4, 0xd4, 0xa6,
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

        let (file, crc) = parse_debug_link_section_data(buffer).unwrap().unwrap();
        assert_eq!(file, OsStr::new("program.debug"));
        assert_eq!(crc, 0xa6d4c469, "{crc:#x}");
    }

    /// Check that we can successfully read an ELF file's debug link.
    #[test]
    fn debug_link_reading() {
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-stripped-with-link.bin");

        let parser = ElfParser::open(&elf).unwrap();
        let (file, crc) = read_debug_link(&parser).unwrap().unwrap();
        assert_eq!(file, OsStr::new("test-stable-addrs-dwarf-only.dbg"));

        let dbg = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let mmap = Mmap::builder().open(dbg).unwrap();
        assert_eq!(crc, debug_link_crc32(&mmap));
    }

    /// Make sure that we can iterate over all debug file target candidates as
    /// expected.
    #[test]
    fn debug_file_iteration() {
        let fixed_dirs = [PathBuf::from("/usr/lib/debug")];
        let files = DebugFileIter::new(fixed_dirs.as_slice(), None, OsStr::new("libc.so.debug"))
            .collect::<Vec<_>>();
        let expected = vec![PathBuf::from("/usr/lib/debug/libc.so.debug")];
        assert_eq!(files, expected);

        let fixed_dirs = DEFAULT_DEBUG_DIRS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let files = DebugFileIter::new(fixed_dirs.as_slice(), None, OsStr::new("libc.so.debug"))
            .collect::<Vec<_>>();
        let expected = vec![
            PathBuf::from("/usr/lib/debug/libc.so.debug"),
            PathBuf::from("/lib/debug/libc.so.debug"),
        ];
        assert_eq!(files, expected);

        let fixed_dirs = [PathBuf::from("/usr/lib/debug/")];
        let files = DebugFileIter::new(
            fixed_dirs.as_slice(),
            Some(Path::new("/usr/lib64/libc.so")),
            OsStr::new("libc.so.debug"),
        )
        .collect::<Vec<_>>();

        let expected = vec![
            PathBuf::from("/usr/lib/debug/libc.so.debug"),
            PathBuf::from("/usr/lib64/libc.so.debug"),
            PathBuf::from("/usr/lib/debug/usr/lib64/libc.so.debug"),
            PathBuf::from("/usr/lib/debug/usr/libc.so.debug"),
        ];
        assert_eq!(files, expected);

        let fixed_dirs = [
            PathBuf::from("/usr/lib/debug"),
            PathBuf::from("/lib/debug/"),
        ];
        let files = DebugFileIter::new(
            fixed_dirs.as_slice(),
            Some(Path::new("/usr/lib64/libc.so")),
            OsStr::new("libc.so.debug"),
        )
        .collect::<Vec<_>>();

        let expected = vec![
            PathBuf::from("/usr/lib/debug/libc.so.debug"),
            PathBuf::from("/lib/debug/libc.so.debug"),
            PathBuf::from("/usr/lib64/libc.so.debug"),
            PathBuf::from("/usr/lib/debug/usr/lib64/libc.so.debug"),
            PathBuf::from("/usr/lib/debug/usr/libc.so.debug"),
            PathBuf::from("/lib/debug/usr/lib64/libc.so.debug"),
            PathBuf::from("/lib/debug/usr/libc.so.debug"),
        ];
        assert_eq!(files, expected);
    }
}

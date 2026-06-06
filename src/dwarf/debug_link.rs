//! Support for reading of GNU debug link data.
//!
//! From <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html>:
//!
//! A debug link is a special section of the executable file named
//! `.gnu_debuglink`. The section must contain:
//! - A filename, with any leading directory components removed, followed by a
//!   zero byte,
//! - zero to three bytes of padding, as needed to reach the next four-byte
//!   boundary within the section, and
//! - a four-byte CRC checksum, stored in the same endianness used for the
//!   executable file itself. The checksum is computed on the debugging
//!   information file's full contents by the function given below, passing zero
//!   as the crc argument.

use std::ffi::OsStr;
use std::mem::take;
use std::path::Path;
use std::path::PathBuf;

use crate::elf::ElfParser;
use crate::elf::BUILD_ID_DEBUG_DIR;
use crate::elf::BUILD_ID_DEBUG_EXTENSION;
use crate::error::IntoError as _;
use crate::util::align_up_usize;
use crate::util::bytes_to_os_str;
use crate::util::ReadRaw as _;
use crate::BuildId;
use crate::Result;


enum State {
    BuildId,
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
    /// The build id of the binary.
    build_id: Option<BuildId<'path>>,
    /// The iteration state.
    state: State,
}

impl<'path> DebugFileIter<'path> {
    pub(crate) fn new(
        fixed_dirs: &'path [PathBuf],
        canonical_linker: Option<&'path Path>,
        linkee: &'path OsStr,
        build_id: Option<BuildId<'path>>,
    ) -> Self {
        Self {
            fixed_dirs,
            canonical_linker,
            linkee,
            build_id,
            state: State::BuildId,
        }
    }

    fn report_or_next(&mut self, path: PathBuf) -> Option<PathBuf> {
        // If the linkee name equals the linker name we may end
        // up reporting the linker itself. Don't do that.
        // Arguably it's questionable whether the debug
        // information is kosher, but just ignoring a
        // self-referential link seems appropriate here.
        if Some(path.as_path()) != self.canonical_linker {
            Some(path)
        } else {
            self.next()
        }
    }
}

impl Iterator for DebugFileIter<'_> {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            State::BuildId => {
                self.state = State::FixedDir { idx: 0 };

                let Some(build_id) = self.build_id.as_ref() else {
                    return self.next()
                };

                // Technically we can check just 2 bytes with the code below,
                // but anything that short is probably bogus and worth skipping.
                if build_id.len() < 8 {
                    return self.next();
                }

                let mut path = PathBuf::from(BUILD_ID_DEBUG_DIR);
                let mut build_id_iter = build_id.iter();

                // SANITY: We guarantee a minimum build ID length above.
                let first = build_id_iter.next().unwrap();
                path.push(format!("{first:02x}"));

                path.push(format!(
                    "{}.{BUILD_ID_DEBUG_EXTENSION}",
                    build_id_iter
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ));

                self.report_or_next(path)
            }
            State::FixedDir { idx } => {
                if let Some(dir) = self.fixed_dirs.get(*idx) {
                    *idx += 1;

                    self.report_or_next(dir.join(self.linkee))
                } else {
                    // We covered all the "fixed" directories. Move on to the
                    // dynamic stuff, if possible.
                    if let Some(linker) = self.canonical_linker {
                        let mut path = linker.to_path_buf();
                        let () = path.set_file_name(self.linkee);

                        self.state = State::CanonicalTarget {
                            canonical_linkee: path,
                        };
                        self.next()
                    } else {
                        None
                    }
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

                self.report_or_next(result)
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
                    self.report_or_next(fixed_dir.join(dir).join(self.linkee))
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
    let crc_offset = align_up_usize(cur_offset, align);
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
    crc32fast::hash(data)
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

        let parser = ElfParser::open(elf.as_path()).unwrap();
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
        let files = DebugFileIter::new(
            fixed_dirs.as_slice(),
            None,
            OsStr::new("libc.so.debug"),
            None,
        )
        .collect::<Vec<_>>();
        let expected = vec![PathBuf::from("/usr/lib/debug/libc.so.debug")];
        assert_eq!(files, expected);

        let fixed_dirs = DEFAULT_DEBUG_DIRS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let files = DebugFileIter::new(
            fixed_dirs.as_slice(),
            None,
            OsStr::new("libc.so.debug"),
            None,
        )
        .collect::<Vec<_>>();
        let expected = vec![
            PathBuf::from("/usr/lib/debug/libc.so.debug"),
            PathBuf::from("/lib/debug/libc.so.debug"),
        ];
        assert_eq!(files, expected);

        // All build IDs are too short.
        for build_id in [vec![], vec![0xbe], vec![0xbe, 0xef, 0xbe, 0xef]] {
            let fixed_dirs = [PathBuf::from("/usr/lib/debug/")];
            let files = DebugFileIter::new(
                fixed_dirs.as_slice(),
                Some(Path::new("/usr/lib64/libc.so")),
                OsStr::new("libc.so.debug"),
                Some(BuildId::Owned(build_id)),
            )
            .collect::<Vec<_>>();

            let expected = vec![
                PathBuf::from("/usr/lib/debug/libc.so.debug"),
                PathBuf::from("/usr/lib64/libc.so.debug"),
                PathBuf::from("/usr/lib/debug/usr/lib64/libc.so.debug"),
                PathBuf::from("/usr/lib/debug/usr/libc.so.debug"),
            ];
            assert_eq!(files, expected);
        }

        let fixed_dirs = [
            PathBuf::from("/usr/lib/debug"),
            PathBuf::from("/lib/debug/"),
        ];
        let files = DebugFileIter::new(
            fixed_dirs.as_slice(),
            Some(Path::new("/usr/lib64/libc.so")),
            OsStr::new("libc.so.debug"),
            Some(BuildId::Owned(vec![
                0xbe, 0xef, 0xbe, 0xef, 0xfe, 0xed, 0xba, 0xbe,
            ])),
        )
        .collect::<Vec<_>>();

        let expected = vec![
            PathBuf::from("/usr/lib/debug/.build-id/be/efbeeffeedbabe.debug"),
            PathBuf::from("/usr/lib/debug/libc.so.debug"),
            PathBuf::from("/lib/debug/libc.so.debug"),
            PathBuf::from("/usr/lib64/libc.so.debug"),
            PathBuf::from("/usr/lib/debug/usr/lib64/libc.so.debug"),
            PathBuf::from("/usr/lib/debug/usr/libc.so.debug"),
            PathBuf::from("/lib/debug/usr/lib64/libc.so.debug"),
            PathBuf::from("/lib/debug/usr/libc.so.debug"),
        ];
        assert_eq!(files, expected);

        // Make sure that we don't report the "linker" itself as a
        // potential linkee.
        let fixed_dirs = [];
        let files = DebugFileIter::new(
            fixed_dirs.as_slice(),
            Some(Path::new("/usr/lib64/libc.so")),
            OsStr::new("libc.so"),
            None,
        )
        .collect::<Vec<_>>();
        assert_eq!(files, Vec::<PathBuf>::new());
    }
}

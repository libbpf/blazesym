use std::error::Error as StdError;
use std::fs::File;
use std::io;
use std::io::Read as _;
use std::path::Path;
use std::str;
use std::str::FromStr;

use crate::elf;
use crate::elf::types::ElfN_Nhdr;
use crate::elf::BackendImpl;
use crate::elf::ElfParser;
use crate::util::align_up_u32;
use crate::util::from_radix_16;
use crate::util::split_bytes;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;

use super::normalizer::Output;


/// The absolute path to the `kcore` `proc` node.
const PROC_KCORE: &str = "/proc/kcore";
/// The name of the `VMCOREINFO` ELF note.
///
/// See https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html
const VMCOREINFO_NAME: &[u8] = b"VMCOREINFO\0";


/// "Parse" the VMCOREINFO descriptor.
///
/// This underspecified blob roughly has the following format:
/// ```
/// OSRELEASE=6.2.15-100.fc36.x86_64
/// BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
/// PAGESIZE=4096
/// SYMBOL(init_uts_ns)=ffffffffb72b8160
/// OFFSET(uts_namespace.name)=0
/// [...]
/// ```
fn parse_vmcoreinfo_desc(desc: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    desc.split(|&b| b == b'\n')
        .filter_map(|line| split_bytes(line, |b| b == b'='))
}

/// Find and read the `KERNELOFFSET` note in a "kcore" file represented by
/// `parser` (i.e., already opened as an ELF).
fn find_kaslr_offset(parser: &ElfParser<File>) -> Result<Option<u64>> {
    let phdrs = parser.program_headers()?;
    for phdr in phdrs.iter(0) {
        if phdr.type_() != elf::types::PT_NOTE {
            continue
        }

        let file = parser.backend();
        let mut offset = phdr.offset();

        // Iterate through all available notes. See `elf(5)` for
        // details.
        while offset + (size_of::<ElfN_Nhdr>() as u64) <= phdr.file_size() {
            let nhdr = file
                .read_pod_obj::<ElfN_Nhdr>(offset)
                .context("failed to read kcore note header")?;
            offset += size_of::<ElfN_Nhdr>() as u64;

            let name = if nhdr.n_namesz > 0 {
                let name = file.read_pod_slice::<u8>(offset, nhdr.n_namesz as _)?;
                offset += u64::from(align_up_u32(nhdr.n_namesz, 4));
                Some(name)
            } else {
                None
            };

            // We are looking for the note named `VMCOREINFO`.
            if name.as_deref() == Some(VMCOREINFO_NAME) {
                if nhdr.n_descsz > 0 {
                    let desc = file.read_pod_slice::<u8>(offset, nhdr.n_descsz as _)?;
                    let offset = parse_vmcoreinfo_desc(&desc)
                        .find(|(key, _value)| key == b"KERNELOFFSET")
                        // The value is in hexadecimal format. Go figure.
                        .map(|(_key, value)| {
                            from_radix_16(value).ok_or_invalid_data(|| {
                                format!("failed to parse KERNELOFFSET value `{value:x?}`")
                            })
                        })
                        .transpose();
                    return offset
                }

                // There shouldn't be multiple notes with that name,
                // but I suppose it can't hurt to keep checking...?
            }

            offset += u64::from(align_up_u32(nhdr.n_descsz, 4));
        }
    }
    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::ErrorKind;


    /// Check that we can parse a dummy VMCOREINFO descriptor.
    #[test]
    fn vmcoreinfo_desc_parsing() {
        let desc = b"OSRELEASE=6.2.15-100.fc36.x86_64
BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
SYMBOL(init_uts_ns)=ffffffffb72b8160
OFFSET(uts_namespace.name)=0
PAGESIZE=4096
";

        let page_size = parse_vmcoreinfo_desc(desc)
            .find(|(key, _value)| key == b"PAGESIZE")
            .map(|(_key, value)| value)
            .unwrap();
        assert_eq!(page_size, b"4096");
    }

    /// Check that we can determine the system's KASLR state.
    #[test]
    fn kaslr_offset_reading() {
        // Always attempt reading the KASLR to exercise the VMCOREINFO
        // parsing path.
        // Note that we cannot use the regular mmap based ELF parser
        // backend for this file, as it cannot be mmap'ed. We have to
        // fall back to using regular I/O instead.
        let parser = match ElfParser::open_non_mmap(PROC_KCORE) {
            Ok(parser) => parser,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("{err}"),
        };
        // We care about the parsing logic, but can't make any claims
        // about the expected offset at this point.
        let _offset = find_kaslr_offset(&parser).unwrap();
    }
}

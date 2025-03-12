use std::borrow::Cow;
use std::mem::size_of;
use std::path::Path;

use crate::elf;
use crate::elf::types::ElfN_Nhdr;
use crate::elf::ElfParser;
use crate::util::align_up_u32;
use crate::util::ReadRaw as _;
use crate::IntoError as _;
use crate::Mmap;
use crate::Result;


/// A GNU build ID, as raw bytes.
pub type BuildId<'src> = Cow<'src, [u8]>;


/// Iterate over all note sections to find one of type
/// [`NT_GNU_BUILD_ID`][elf::types::NT_GNU_BUILD_ID].
pub(crate) fn read_build_id(parser: &ElfParser) -> Result<Option<BuildId<'_>>> {
    let shdrs = parser.section_headers()?;
    for (idx, shdr) in shdrs.iter(0).enumerate() {
        if shdr.type_() == elf::types::SHT_NOTE {
            // SANITY: We just found the index so the section data should always
            //         be found.
            let mut bytes = parser.section_data(idx).unwrap();

            while bytes.len() >= size_of::<ElfN_Nhdr>() {
                let nhdr = bytes
                    .read_pod_ref::<ElfN_Nhdr>()
                    .ok_or_invalid_data(|| "failed to read build ID section header")?;

                // Type check is assumed to suffice, but we still need
                // to skip the name bytes.
                let () = bytes
                    .advance(align_up_u32(nhdr.n_namesz, 4) as _)
                    .ok_or_invalid_data(|| "failed to skip over ELF note name")?;

                if nhdr.n_type == elf::types::NT_GNU_BUILD_ID {
                    let build_id = bytes
                        .read_slice(nhdr.n_descsz as _)
                        .ok_or_invalid_data(|| "failed to read build ID section contents")?;
                    return Ok(Some(Cow::Borrowed(build_id)))
                } else {
                    let () = bytes
                        .advance(align_up_u32(nhdr.n_descsz, 4) as _)
                        .ok_or_invalid_data(|| "failed to skip over ELF note descriptor")?;
                }
            }
        }
    }
    Ok(None)
}


/// Read the build ID of an ELF file located at the given path.
///
/// Build IDs can have variable length, depending on which flavor is used (e.g.,
/// 20 bytes for `sha1` flavor). They are reported as "raw" bytes. If you need a
/// hexadecimal representation as reported by tools such as `readelf(1)`, a post
/// processing step is necessary.
///
/// Returns [`None`] if the file does not contain a build ID.
///
/// # Examples
/// ```
/// # use std::path::Path;
/// # let retrieve_path_to_elf_file = || {
/// #   Path::new(&env!("CARGO_MANIFEST_DIR"))
/// #       .join("data")
/// #       .join("libtest-so.so")
/// #       // Convert to string here for more convenient formatting in example
/// #       // code.
/// #       .to_str()
/// #       .unwrap()
/// #       .to_string()
/// # };
/// let path = retrieve_path_to_elf_file();
/// let build_id = blazesym::helper::read_elf_build_id(&path).unwrap();
/// match build_id {
///     Some(bytes) => {
///        let build_id = bytes
///            .iter()
///            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
///                let () = s.push_str(&format!("{b:02x}"));
///                s
///            });
///        println!("{path} has build ID {build_id}");
///     },
///     None => println!("{path} has no build ID"),
/// }
/// ```
#[inline]
pub fn read_elf_build_id<P>(path: &P) -> Result<Option<BuildId<'static>>>
where
    P: AsRef<Path> + ?Sized,
{
    let parser = ElfParser::open(path.as_ref())?;
    let buildid = read_build_id(&parser)?.map(|buildid| Cow::Owned(buildid.to_vec()));
    Ok(buildid)
}

/// Read a build ID of a memory mapped ELF file.
///
/// This function is similar in purpose to [`read_elf_build_id`], but is able to
/// work on an already memory mapped ELF file.
// TODO: Ideally we'd just provide a byte slice here instead, but that is not
//       feasible at this point.
#[inline]
pub fn read_elf_build_id_from_mmap(mmap: &Mmap) -> Result<Option<BuildId<'static>>> {
    let parser = ElfParser::from_mmap(mmap.clone(), None);
    let buildid = read_build_id(&parser)?.map(|buildid| Cow::Owned(buildid.to_vec()));
    Ok(buildid)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use test_log::test;
    use test_tag::tag;

    use crate::ErrorKind;
    use crate::Result;


    /// Check that we can read a binary's build ID based on the ELF section name
    /// as well as ELF section type.
    #[tag(other_os)]
    #[test]
    fn build_id_reading_from_name_and_notes() {
        fn test(file: &str, f: fn(&ElfParser) -> Result<Option<BuildId>>) {
            let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(file);

            let parser = ElfParser::open(elf.as_path()).unwrap();
            let build_id = f(&parser).unwrap().unwrap();
            // The file contains a sha1 build ID, which is always 20 bytes long.
            assert_eq!(build_id.len(), 20, "'{build_id:?}'");
        }

        test("libtest-so.so", read_build_id);
        test("libtest-so-32.so", read_build_id);
    }

    /// Check that we can read a binary's build ID.
    #[tag(other_os)]
    #[test]
    fn build_id_reading() {
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let build_id = read_elf_build_id(&elf).unwrap().unwrap();
        // The file contains a sha1 build ID, which is always 20 bytes in length.
        assert_eq!(build_id.len(), 20, "'{build_id:?}'");

        let file = File::open(&elf).unwrap();
        let mmap = Mmap::map(&file).unwrap();
        let build_id = read_elf_build_id_from_mmap(&mmap).unwrap().unwrap();
        assert_eq!(build_id.len(), 20, "'{build_id:?}'");

        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so-no-separate-code.so");
        let build_id = read_elf_build_id(&elf).unwrap().unwrap();
        // The file contains an md5 build ID, which is always 16 bytes long.
        assert_eq!(build_id.len(), 16, "'{build_id:?}'");

        // The shared object is explicitly built without build ID.
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");
        let build_id = read_elf_build_id(&elf).unwrap();
        assert_eq!(build_id, None);

        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("does-not-exist");
        let err = read_elf_build_id(&elf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

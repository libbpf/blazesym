use std::borrow::Cow;
use std::path::Path;

use crate::elf;
use crate::elf::types::Elf64_Nhdr;
use crate::elf::ElfParser;
use crate::file_cache::FileCache;
use crate::log::warn;
use crate::util::ReadRaw as _;
use crate::Error;
use crate::IntoError as _;
use crate::Mmap;
use crate::Result;


/// A GNU build ID, as raw bytes.
pub type BuildId<'src> = Cow<'src, [u8]>;


/// Iterate over all note sections to find one of type
/// [`NT_GNU_BUILD_ID`][elf::types::NT_GNU_BUILD_ID].
fn read_build_id_from_notes(parser: &ElfParser) -> Result<Option<BuildId<'_>>> {
    let shdrs = parser.section_headers()?;
    for (idx, shdr) in shdrs.iter().enumerate() {
        if shdr.sh_type == elf::types::SHT_NOTE {
            // SANITY: We just found the index so the section data should always
            //         be found.
            let mut bytes = parser.section_data(idx).unwrap();
            let header = bytes
                .read_pod_ref::<Elf64_Nhdr>()
                .ok_or_invalid_data(|| "failed to read build ID section header")?;
            if header.n_type == elf::types::NT_GNU_BUILD_ID {
                // Type check is assumed to suffice, but we still need
                // to skip the name bytes.
                let _name = bytes
                    .read_slice(header.n_namesz as _)
                    .ok_or_invalid_data(|| "failed to read build ID section name")?;
                let build_id = bytes
                    .read_slice(header.n_descsz as _)
                    .ok_or_invalid_data(|| "failed to read build ID section contents")?;
                return Ok(Some(Cow::Borrowed(build_id)))
            }
        }
    }
    Ok(None)
}

/// Attempt to read an ELF binary's build ID from the .note.gnu.build-id
/// section.
fn read_build_id_from_section_name(parser: &ElfParser) -> Result<Option<BuildId<'_>>> {
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
        let header = bytes
            .read_pod_ref::<Elf64_Nhdr>()
            .ok_or_invalid_data(|| "failed to read build ID section header")?;
        let name = bytes
            .read_slice(header.n_namesz as _)
            .and_then(|mut name| name.read_cstr())
            .ok_or_invalid_data(|| "failed to read build ID section name")?;
        if name.to_bytes() != b"GNU" {
            warn!("encountered unsupported build ID type {:?}; ignoring", name);
            Ok(None)
        } else {
            let build_id = bytes
                .read_slice(header.n_descsz as _)
                .ok_or_invalid_data(|| "failed to read build ID section contents")?;
            Ok(Some(Cow::Borrowed(build_id)))
        }
    } else {
        Ok(None)
    }
}


fn read_build_id_impl(parser: &ElfParser) -> Result<Option<BuildId>> {
    if let Some(build_id) = read_build_id_from_section_name(parser)? {
        Ok(Some(build_id))
    } else if let Some(build_id) = read_build_id_from_notes(parser)? {
        Ok(Some(build_id))
    } else {
        Ok(None)
    }
}

pub(super) trait BuildIdReader<'src> {
    fn read_build_id(&self, path: &Path) -> Option<BuildId<'src>> {
        #[cfg_attr(
            feature = "tracing",
            crate::log::instrument(err, skip_all, fields(path = ?path))
        )]
        fn read_build_id<'src, B>(slf: &B, path: &Path) -> Result<Option<BuildId<'src>>>
        where
            B: BuildIdReader<'src> + ?Sized,
        {
            slf.read_build_id_fallible(path)
        }

        read_build_id(self, path).ok().flatten()
    }

    fn read_build_id_fallible(&self, path: &Path) -> Result<Option<BuildId<'src>>>;
}


pub(super) struct DefaultBuildIdReader;

impl BuildIdReader<'_> for DefaultBuildIdReader {
    /// Attempt to read an ELF binary's build ID from a file.
    fn read_build_id_fallible(&self, path: &Path) -> Result<Option<BuildId<'static>>> {
        let parser = ElfParser::open(path)?;
        let buildid = read_build_id_impl(&parser)?.map(|buildid| Cow::Owned(buildid.to_vec()));
        Ok(buildid)
    }
}


pub(super) struct CachingBuildIdReader<'cache> {
    /// The build ID cache.
    cache: &'cache FileCache<Option<BuildId<'static>>>,
}

impl<'cache> CachingBuildIdReader<'cache> {
    #[inline]
    pub fn new(cache: &'cache FileCache<Option<BuildId<'static>>>) -> Self {
        Self { cache }
    }
}

impl<'src> BuildIdReader<'src> for CachingBuildIdReader<'src> {
    /// Attempt to read an ELF binary's build ID from a file.
    fn read_build_id_fallible(&self, path: &Path) -> Result<Option<BuildId<'src>>> {
        let (file, cell) = self.cache.entry(path)?;
        let build_id = cell
            .get_or_try_init(|| {
                let parser = ElfParser::open_file(file, path)?;
                let buildid =
                    read_build_id_impl(&parser)?.map(|buildid| Cow::Owned(buildid.to_vec()));
                Result::<_, Error>::Ok(buildid)
            })?
            .as_deref()
            .map(Cow::Borrowed);
        Ok(build_id)
    }
}


pub(super) struct NoBuildIdReader;

impl BuildIdReader<'_> for NoBuildIdReader {
    #[inline]
    fn read_build_id_fallible(&self, _path: &Path) -> Result<Option<BuildId<'static>>> {
        Ok(None)
    }
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
    let buildid = read_build_id_impl(&parser)?.map(|buildid| Cow::Owned(buildid.to_vec()));
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
    let buildid = read_build_id_impl(&parser)?.map(|buildid| Cow::Owned(buildid.to_vec()));
    Ok(buildid)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use test_log::test;

    use crate::ErrorKind;


    /// Check that we can read a binary's build ID based on the ELF section name
    /// as well as ELF section type.
    #[test]
    fn build_id_reading_from_name_and_notes() {
        fn test(f: fn(&ElfParser) -> Result<Option<BuildId>>) {
            let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("libtest-so.so");

            let parser = ElfParser::open(&elf).unwrap();
            let build_id = f(&parser).unwrap().unwrap();
            // The file contains a sha1 build ID, which is always 20 bytes long.
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

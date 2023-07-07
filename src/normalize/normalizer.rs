use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::marker::PhantomData;
use std::path::Path;
use std::path::PathBuf;

use crate::elf;
use crate::elf::ElfParser;
use crate::maps;
use crate::maps::PathMapsEntry;
use crate::util;
use crate::zip;
use crate::Addr;
use crate::Pid;

use super::buildid::BuildIdFn;
use super::buildid::BuildIdReader;
use super::buildid::DefaultBuildIdReader;
use super::buildid::ElfBuildIdFn;
use super::meta::ApkElf;
use super::meta::Elf;
use super::meta::Unknown;
use super::meta::UserAddrMeta;


pub(crate) fn create_apk_elf_path(apk: &Path, elf: &Path) -> Result<PathBuf> {
    let mut extension = apk
        .extension()
        .unwrap_or_else(|| OsStr::new("apk"))
        .to_os_string();
    // Append '!' to indicate separation from archive internal contents
    // that follow. This is an Android convention.
    let () = extension.push("!");

    let mut apk = apk.to_path_buf();
    if !apk.set_extension(extension) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("path {} is not valid", apk.display()),
        ))
    }

    let path = apk.join(elf);
    Ok(path)
}


/// A type capturing normalized addresses along with captured meta data.
///
/// This type enables "remote" symbolization. That is to say, it represents the
/// input necessary for addresses to be symbolized on a system other than where
/// they were recorded.
#[derive(Clone, Debug)]
pub struct NormalizedAddrs<M> {
    /// Normalized addresses along with an index into `meta` for retrieval of
    /// the corresponding [`AddrMeta`] information.
    ///
    /// A normalized address is one as it would appear in a binary or debug
    /// symbol file, i.e., one excluding any relocations.
    pub addrs: Vec<(Addr, usize)>,
    /// Meta information about the normalized addresses.
    pub meta: Vec<M>,
}

/// A type representing normalized user addresses.
pub type NormalizedUserAddrs = NormalizedAddrs<UserAddrMeta>;


fn normalize_elf_offset_with_parser(offset: u64, parser: &ElfParser) -> Result<Option<Addr>> {
    let phdrs = parser.program_headers()?;
    let addr = phdrs.iter().find_map(|phdr| {
        if phdr.p_type == elf::types::PT_LOAD {
            if (phdr.p_offset..phdr.p_offset + phdr.p_memsz).contains(&offset) {
                return Some((offset - phdr.p_offset + phdr.p_vaddr) as Addr)
            }
        }
        None
    });

    Ok(addr)
}


/// Make a [`UserAddrMeta::Elf`] variant.
fn make_elf_meta(entry: &PathMapsEntry, get_build_id: &BuildIdFn) -> Result<UserAddrMeta> {
    let elf = Elf {
        path: entry.path.symbolic_path.to_path_buf(),
        build_id: get_build_id(&entry.path.maps_file)?,
        _non_exhaustive: (),
    };
    let meta = UserAddrMeta::Elf(elf);
    Ok(meta)
}


/// Make a [`UserAddrMeta::ApkElf`] variant.
fn make_apk_elf_meta(
    entry: &PathMapsEntry,
    elf_path: PathBuf,
    elf_parser: &ElfParser,
    get_build_id: &ElfBuildIdFn,
) -> Result<UserAddrMeta> {
    let apk = ApkElf {
        elf_build_id: get_build_id(elf_parser)?,
        apk_path: entry.path.symbolic_path.to_path_buf(),
        elf_path,
        _non_exhaustive: (),
    };
    let meta = UserAddrMeta::ApkElf(apk);
    Ok(meta)
}


/// Normalize a virtual address belonging to an ELF file represented by the
/// provided [`PathMapsEntry`].
pub(crate) fn normalize_elf_addr(virt_addr: Addr, entry: &PathMapsEntry) -> Result<Addr> {
    let file_off = virt_addr as u64 - entry.range.start as u64 + entry.offset;
    let parser = ElfParser::open(&entry.path.maps_file)?;
    let addr = normalize_elf_offset_with_parser(file_off, &parser)?.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!(
                "failed to find ELF segment in {} that contains file offset 0x{:x}",
                entry.path.symbolic_path.display(),
                entry.offset,
            ),
        )
    })?;

    Ok(addr)
}


/// Normalize a virtual address belonging to an APK represented by the provided
/// [`PathMapsEntry`].
pub(crate) fn normalize_apk_addr(
    virt_addr: Addr,
    entry: &PathMapsEntry,
) -> Result<(Addr, PathBuf, ElfParser)> {
    let file_off = virt_addr - entry.range.start + entry.offset as usize;
    // An APK is nothing but a fancy zip archive.
    let apk = zip::Archive::open(&entry.path.maps_file)?;

    // Find the APK entry covering the calculated file offset.
    for apk_entry in apk.entries() {
        let apk_entry = apk_entry?;
        let bounds = apk_entry.data_offset..apk_entry.data_offset + apk_entry.data.len();

        if bounds.contains(&file_off) {
            let mmap = apk.mmap().constrain(bounds.clone()).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "invalid APK entry data bounds ({bounds:?}) in {}",
                        entry.path.symbolic_path.display()
                    ),
                )
            })?;
            let parser = ElfParser::from_mmap(mmap);
            let elf_off = file_off - apk_entry.data_offset;
            if let Some(addr) = normalize_elf_offset_with_parser(elf_off as u64, &parser)? {
                return Ok((addr, apk_entry.path.to_path_buf(), parser))
            }
            break
        }
    }

    Err(Error::new(
        ErrorKind::InvalidInput,
        format!(
            "failed to find ELF entry in {} that contains file offset 0x{:x}",
            entry.path.symbolic_path.display(),
            file_off,
        ),
    ))
}


impl NormalizedUserAddrs {
    /// Add an unknown (non-normalizable) address to this object.
    ///
    /// This function accepts `unknown_idx` which, if not `None`, should
    /// contain the index into [`Self::meta`] at which an [`Unknown`]
    /// without any build ID resides.
    ///
    /// It returns the index of the inserted [`Unknown`] variant. The
    /// return type is an `Option` only for convenience of callers.
    /// Returned is always a `Some`.
    fn add_unknown_addr(&mut self, addr: Addr, unknown_idx: Option<usize>) -> Option<usize> {
        let unknown_idx = if let Some(unknown_idx) = unknown_idx {
            debug_assert_eq!(self.meta[unknown_idx], Unknown::default().into());
            unknown_idx
        } else {
            let unknown_idx = self.meta.len();
            let unknown = Unknown::default();
            let () = self.meta.push(UserAddrMeta::Unknown(unknown));
            unknown_idx
        };

        let () = self.addrs.push((addr, unknown_idx));
        Some(unknown_idx)
    }

    /// Add a normalized address to this object.
    fn add_normalized_addr<F>(
        &mut self,
        norm_addr: Addr,
        key: &Path,
        meta_lookup: &mut HashMap<PathBuf, usize>,
        create_meta: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<UserAddrMeta>,
    {
        let meta_idx = if let Some(meta_idx) = meta_lookup.get(key) {
            *meta_idx
        } else {
            let meta = create_meta()?;
            let meta_idx = self.meta.len();
            let () = self.meta.push(meta);
            let _ref = meta_lookup.insert(key.to_path_buf(), meta_idx);
            meta_idx
        };

        let () = self.addrs.push((norm_addr, meta_idx));
        Ok(())
    }
}


pub(crate) trait Handler {
    /// Handle an unknown address.
    fn handle_unknown_addr(&mut self, addr: Addr) -> Result<()>;

    /// Handle an address residing in the provided [`PathMapsEntry`].
    fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()>;
}


struct NormalizationHandler<R> {
    /// The normalized user addresses we are building up.
    normalized: NormalizedUserAddrs,
    /// Lookup table from path (as used in each proc maps entry) to index into
    /// `normalized.meta`.
    meta_lookup: HashMap<PathBuf, usize>,
    /// The index of the `Unknown` entry in `meta_lookup`, used for all unknown
    /// addresses.
    unknown_idx: Option<usize>,
    #[doc(hidden)]
    _phanton: PhantomData<R>,
}

impl<R> NormalizationHandler<R> {
    /// Instantiate a new `NormalizationHandler` object.
    fn new(addr_count: usize) -> Self {
        Self {
            normalized: NormalizedUserAddrs {
                addrs: Vec::with_capacity(addr_count),
                meta: Vec::new(),
            },
            meta_lookup: HashMap::<PathBuf, usize>::new(),
            unknown_idx: None,
            _phanton: PhantomData,
        }
    }
}

impl<R> NormalizationHandler<R>
where
    R: BuildIdReader,
{
    /// Normalize a virtual address belonging to an APK and create and add the
    /// correct [`UserAddrMeta`] meta information.
    fn normalize_and_add_apk_addr(&mut self, virt_addr: Addr, entry: &PathMapsEntry) -> Result<()> {
        let (norm_addr, elf_path, elf_parser) = normalize_apk_addr(virt_addr, entry)?;
        let key = create_apk_elf_path(&entry.path.symbolic_path, &elf_path)?;
        let () =
            self.normalized
                .add_normalized_addr(norm_addr, &key, &mut self.meta_lookup, || {
                    make_apk_elf_meta(entry, elf_path, &elf_parser, &R::read_build_id)
                })?;

        Ok(())
    }

    /// Normalize a virtual address belonging to an ELF file and create and add
    /// the correct [`UserAddrMeta`] meta information.
    fn normalize_and_add_elf_addr(&mut self, virt_addr: Addr, entry: &PathMapsEntry) -> Result<()> {
        let norm_addr = normalize_elf_addr(virt_addr, entry)?;
        let () = self.normalized.add_normalized_addr(
            norm_addr,
            &entry.path.symbolic_path,
            &mut self.meta_lookup,
            || make_elf_meta(entry, &R::read_build_id_from_elf),
        )?;

        Ok(())
    }
}

impl<R> Handler for NormalizationHandler<R>
where
    R: BuildIdReader,
{
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("0x{addr:x}"))))]
    fn handle_unknown_addr(&mut self, addr: Addr) -> Result<()> {
        self.unknown_idx = self.normalized.add_unknown_addr(addr, self.unknown_idx);
        Ok(())
    }

    fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
        let ext = entry
            .path
            .symbolic_path
            .extension()
            .unwrap_or_else(|| OsStr::new(""));
        match ext.to_str() {
            Some("apk") | Some("zip") => self.normalize_and_add_apk_addr(addr, entry),
            _ => self.normalize_and_add_elf_addr(addr, entry),
        }
    }
}


pub(crate) fn normalize_sorted_user_addrs_with_entries<A, E, H>(
    addrs: A,
    entries: E,
    mut handler: H,
) -> Result<H>
where
    A: ExactSizeIterator<Item = Addr> + Clone,
    E: Iterator<Item = Result<maps::MapsEntry>>,
    H: Handler,
{
    let mut entries = entries.filter_map(|result| match result {
        Ok(entry) => maps::filter_map_relevant(entry).map(Ok),
        Err(err) => Some(Err(err)),
    });

    let mut entry = entries.next().ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "proc maps does not contain relevant entries",
        )
    })??;

    let mut prev_addr = addrs.clone().next().unwrap_or_default();
    // We effectively do a single pass over `addrs`, advancing to the next
    // proc maps entry whenever the current address is not (or no longer)
    // contained in the current entry's range.
    'main: for addr in addrs {
        if addr < prev_addr {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "addresses to normalize are not sorted",
            ))
        }
        prev_addr = addr;

        while addr >= entry.range.end {
            entry = if let Some(entry) = entries.next() {
                entry?
            } else {
                // If there are no proc maps entries left to check, we
                // cannot normalize. We have to assume that addresses
                // were valid and the ELF object was just unmapped,
                // similar to above.
                let () = handler.handle_unknown_addr(addr)?;
                continue 'main
            };
        }

        // proc maps entries are always sorted by start address. If the
        // current address lies before the start address at this point,
        // that means that we cannot find a suitable entry. This could
        // happen, for example, if an ELF object was unmapped between
        // address capture and normalization.
        if addr < entry.range.start {
            let () = handler.handle_unknown_addr(addr)?;
            continue 'main
        }

        let () = handler.handle_entry_addr(addr, &entry)?;
    }

    Ok(handler)
}


/// A normalizer for addresses.
///
/// Address normalization is the process of taking virtual absolute
/// addresses as they are seen by, say, a process (which include
/// relocation and process specific layout randomizations, among other
/// things) and converting them to "normalized" virtual addresses as
/// they are present in, say, an ELF binary or a DWARF debug info file,
/// and one would be able to see them using tools such as readelf(1).
#[derive(Debug, Default)]
pub struct Normalizer {
    _private: (),
}

impl Normalizer {
    /// Create a new `Normalizer`.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Normalize all `addrs` in a given process. The `addrs` array has to
    /// be sorted in ascending order or an error will be returned.
    ///
    /// Unknown addresses are not normalized. They are reported as
    /// [`Unknown`] meta entries in the returned [`NormalizedUserAddrs`]
    /// object. The cause of an address to be unknown (and, hence, not
    /// normalized), could have a few reasons, including, but not limited
    /// to:
    /// - user error (if a bogus address was provided)
    /// - they belonged to an ELF object that has been unmapped since the
    ///   address was captured
    ///
    /// The process' ID should be provided in `pid`.
    ///
    /// Normalized addresses are reported in the exact same order in which the
    /// non-normalized ones were provided.
    fn normalize_user_addrs_sorted_impl<A>(&self, addrs: A, pid: Pid) -> Result<NormalizedUserAddrs>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
    {
        let addrs_cnt = addrs.len();
        let entries = maps::parse(pid)?;
        let handler = NormalizationHandler::<DefaultBuildIdReader>::new(addrs_cnt);
        let handler = normalize_sorted_user_addrs_with_entries(addrs, entries, handler)?;
        debug_assert_eq!(handler.normalized.addrs.len(), addrs_cnt);
        Ok(handler.normalized)
    }

    /// Normalize `addresses` belonging to a process.
    ///
    /// Normalize all `addrs` in a given process. The `addrs` array has
    /// to be sorted in ascending order or an error will be returned. By
    /// providing a pre-sorted array the library does not have to sort
    /// internally, which will result in quicker normalization. If you
    /// don't have sorted addresses, use
    /// [`Normalizer::normalize_user_addrs`] instead.
    ///
    /// Unknown addresses are not normalized. They are reported as
    /// [`Unknown`] meta entries in the returned [`NormalizedUserAddrs`]
    /// object. The cause of an address to be unknown (and, hence, not
    /// normalized), could have a few reasons, including, but not limited
    /// to:
    /// - user error (if a bogus address was provided)
    /// - they belonged to an ELF object that has been unmapped since the
    ///   address was captured
    ///
    /// The process' ID should be provided in `pid`.
    ///
    /// Normalized addresses are reported in the exact same order in which the
    /// non-normalized ones were provided.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self)))]
    pub fn normalize_user_addrs_sorted(
        &self,
        addrs: &[Addr],
        pid: Pid,
    ) -> Result<NormalizedUserAddrs> {
        self.normalize_user_addrs_sorted_impl(addrs.iter().copied(), pid)
    }


    /// Normalize `addresses` belonging to a process.
    ///
    /// Normalize all `addrs` in a given process. Contrary to
    /// [`Normalizer::normalize_user_addrs_sorted`], the provided `addrs` array
    /// does not have to be sorted, but otherwise the functions behave
    /// identically. If you do happen to know that `addrs` is sorted, using
    /// [`Normalizer::normalize_user_addrs_sorted`] instead will result in
    /// slightly faster normalization.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self)))]
    pub fn normalize_user_addrs(&self, addrs: &[Addr], pid: Pid) -> Result<NormalizedUserAddrs> {
        util::with_ordered_elems(
            addrs,
            |normalized: &mut NormalizedUserAddrs| normalized.addrs.as_mut_slice(),
            |sorted_addrs| self.normalize_user_addrs_sorted_impl(sorted_addrs, pid),
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::transmute;

    use crate::inspect::FindAddrOpts;
    use crate::inspect::SymType;
    use crate::mmap::Mmap;

    use test_log::test;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf).unwrap();
        assert_eq!(path, Path::new("/root/test.apk!/subdir/libc.so"));
    }

    /// Check that we detect unsorted input addresses.
    #[test]
    fn user_address_normalization_unsorted() {
        let mut addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
        ];
        let () = addrs.sort();
        let () = addrs.swap(0, 1);

        let normalizer = Normalizer::new();
        let err = normalizer
            .normalize_user_addrs_sorted(addrs.as_slice(), Pid::Slf)
            .unwrap_err();
        assert!(err.to_string().contains("are not sorted"), "{err}");
    }

    /// Check that we handle unknown addresses as expected.
    #[test]
    fn user_address_normalization_unknown() {
        // The very first page of the address space should never be
        // mapped, so use addresses from there.
        let addrs = [0x500 as Addr, 0x600 as Addr];

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs_sorted(addrs.as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 2);
        assert_eq!(norm_addrs.meta.len(), 1);
        assert_eq!(norm_addrs.meta[0], Unknown::default().into());
        assert_eq!(norm_addrs.addrs[0].1, 0);
        assert_eq!(norm_addrs.addrs[1].1, 0);
    }

    /// Check that we can normalize user addresses.
    #[test]
    fn user_address_normalization() {
        let addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
            elf_apk_path_creation as Addr,
            user_address_normalization as Addr,
            Mmap::map as Addr,
        ];

        let (errno_idx, _) = addrs
            .iter()
            .enumerate()
            .find(|(_idx, addr)| **addr == libc::__errno_location as Addr)
            .unwrap();

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs(addrs.as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 6);

        let addrs = &norm_addrs.addrs;
        let meta = &norm_addrs.meta;
        assert_eq!(meta.len(), 2);

        let errno_meta_idx = addrs[errno_idx].1;
        assert!(meta[errno_meta_idx]
            .elf()
            .unwrap()
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("libc.so"));
    }

    /// Check that we can normalize user addresses in our own shared object.
    #[test]
    fn user_address_normalization_custom_so() {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");

        let mmap = Mmap::builder().exec().open(test_so).unwrap();
        // Look up the address of the `the_answer` function inside of the shared
        // object.
        let elf_parser = ElfParser::from_mmap(mmap.clone());
        let opts = FindAddrOpts {
            sym_type: SymType::Function,
            ..Default::default()
        };
        let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
        // There is only one symbol with this address in there.
        assert_eq!(syms.len(), 1);
        let sym = syms.first().unwrap();

        let the_answer_addr = unsafe { mmap.as_ptr().add(sym.addr) };
        // Now just double check that everything worked out and the function
        // is actually where it was meant to be.
        let the_answer_fn =
            unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
        let answer = the_answer_fn();
        assert_eq!(answer, 42);

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 1);
        assert_eq!(norm_addrs.meta.len(), 1);

        let norm_addr = norm_addrs.addrs[0];
        assert_eq!(norm_addr.0, sym.addr);
        let meta = &norm_addrs.meta[norm_addr.1];
        let so_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let expected_elf = Elf {
            build_id: Some(
                DefaultBuildIdReader::read_build_id_from_elf(&so_path)
                    .unwrap()
                    .unwrap(),
            ),
            path: so_path,
            _non_exhaustive: (),
        };
        assert_eq!(meta, &UserAddrMeta::Elf(expected_elf));
    }

    /// Check that we can normalize addresses in our own shared object inside a
    /// zip archive.
    #[test]
    fn address_normalization_custom_so_in_zip() {
        fn test(so_name: &str) {
            let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("test.zip");

            let mmap = Mmap::builder().exec().open(&test_zip).unwrap();
            let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
            let so = archive
                .entries()
                .find_map(|entry| {
                    let entry = entry.unwrap();
                    (entry.path == Path::new(so_name)).then_some(entry)
                })
                .unwrap();

            let elf_mmap = mmap
                .constrain(so.data_offset..so.data_offset + so.data.len())
                .unwrap();

            // Look up the address of the `the_answer` function inside of the shared
            // object.
            let elf_parser = ElfParser::from_mmap(elf_mmap.clone());
            let opts = FindAddrOpts {
                sym_type: SymType::Function,
                ..Default::default()
            };
            let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
            // There is only one symbol with this address in there.
            assert_eq!(syms.len(), 1);
            let sym = syms.first().unwrap();

            let the_answer_addr = unsafe { elf_mmap.as_ptr().add(sym.addr) };
            // Now just double check that everything worked out and the function
            // is actually where it was meant to be.
            let the_answer_fn =
                unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
            let answer = the_answer_fn();
            assert_eq!(answer, 42);

            let normalizer = Normalizer::new();
            let norm_addrs = normalizer
                .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
                .unwrap();
            assert_eq!(norm_addrs.addrs.len(), 1);
            assert_eq!(norm_addrs.meta.len(), 1);

            let norm_addr = norm_addrs.addrs[0];
            assert_eq!(norm_addr.0, sym.addr);
            let meta = &norm_addrs.meta[norm_addr.1];
            let so_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(so_name);
            let expected = ApkElf {
                apk_path: test_zip,
                elf_path: PathBuf::from(so_name),
                elf_build_id: Some(
                    DefaultBuildIdReader::read_build_id_from_elf(&so_path)
                        .unwrap()
                        .unwrap(),
                ),
                _non_exhaustive: (),
            };
            assert_eq!(meta, &UserAddrMeta::ApkElf(expected));
        }

        test("libtest-so.so");
        test("libtest-so-no-separate-code.so");
    }

    /// Check that we correctly handle normalization of an address not
    /// in any executable segment.
    #[test]
    fn user_address_normalization_static_maps() {
        struct NoBuildIdReader;

        impl BuildIdReader for NoBuildIdReader {
            fn read_build_id_from_elf(_path: &Path) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn read_build_id(_parser: &ElfParser) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
        }

        fn test(unknown_addr: Addr) {
            let maps = r#"
55d3195b7000-55d3195b9000 r--p 00000000 00:12 2015701                    /bin/cat
55d3195b9000-55d3195be000 r-xp 00002000 00:12 2015701                    /bin/cat
55d3195be000-55d3195c1000 r--p 00007000 00:12 2015701                    /bin/cat
55d3195c1000-55d3195c2000 r--p 00009000 00:12 2015701                    /bin/cat
55d3195c2000-55d3195c3000 rw-p 0000a000 00:12 2015701                    /bin/cat
55d31b4dc000-55d31b4fd000 rw-p 00000000 00:00 0                          [heap]
7fd5b9c3d000-7fd5b9c5f000 rw-p 00000000 00:00 0
7fd5b9c5f000-7fd5ba034000 r--p 00000000 00:12 7689533                    /usr/lib/locale/locale-archive
7fd5ba034000-7fd5ba037000 rw-p 00000000 00:00 0
7fd5ba037000-7fd5ba059000 r--p 00000000 00:12 2088876                    /lib64/libc.so.6
7fd5ba059000-7fd5ba1a8000 r-xp 00022000 00:12 2088876                    /lib64/libc.so.6
7fd5ba1a8000-7fd5ba1fa000 r--p 00171000 00:12 2088876                    /lib64/libc.so.6
7fd5ba1fa000-7fd5ba1fe000 r--p 001c3000 00:12 2088876                    /lib64/libc.so.6
7fd5ba1fe000-7fd5ba200000 rw-p 001c7000 00:12 2088876                    /lib64/libc.so.6
7fd5ba200000-7fd5ba208000 rw-p 00000000 00:00 0
7fd5ba214000-7fd5ba216000 rw-p 00000000 00:00 0
7fd5ba216000-7fd5ba217000 r--p 00000000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba217000-7fd5ba23c000 r-xp 00001000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba23c000-7fd5ba246000 r--p 00026000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba246000-7fd5ba248000 r--p 00030000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7fd5ba248000-7fd5ba24a000 rw-p 00032000 00:12 2088889                    /lib64/ld-linux-x86-64.so.2
7ffe102a2000-7ffe102c4000 rw-p 00000000 00:00 0                          [stack]
7ffe103f6000-7ffe103fa000 r--p 00000000 00:00 0                          [vvar]
7ffe103fa000-7ffe103fc000 r-xp 00000000 00:00 0                          [vdso]
"#;

            let pid = Pid::Slf;
            let entries = maps::parse_file(maps.as_bytes(), pid);
            let addrs = [unknown_addr as Addr];

            let handler = NormalizationHandler::<NoBuildIdReader>::new(addrs.len());
            let norm_addrs = normalize_sorted_user_addrs_with_entries(
                addrs.as_slice().iter().copied(),
                entries,
                handler,
            )
            .unwrap()
            .normalized;
            assert_eq!(norm_addrs.addrs.len(), 1);
            assert_eq!(norm_addrs.meta.len(), 1);
            assert_eq!(norm_addrs.meta[0], Unknown::default().into());
        }

        test(0x0);
        test(0x1);
        test(0x1000);
        test(0xa0000);
        test(0x7fd5ba1fe000);
        test(0x7fffffff0000);
        test(0x7fffffff1000);
        test(0x7fffffff1001);
        test(0x7fffffffffff);
    }
}

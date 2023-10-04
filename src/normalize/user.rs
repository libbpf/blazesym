use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Error;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::path::Path;
use std::path::PathBuf;

use crate::elf;
use crate::elf::ElfParser;
use crate::error::IntoError as _;
use crate::maps;
use crate::maps::PathMapsEntry;
use crate::zip;
use crate::Addr;
use crate::ErrorExt as _;
use crate::Pid;
use crate::Result;

use super::buildid::BuildIdFn;
use super::buildid::BuildIdReader;
use super::buildid::DefaultBuildIdReader;
use super::buildid::ElfBuildIdFn;
use super::buildid::NoBuildIdReader;
use super::meta::ApkElf;
use super::meta::Elf;
use super::meta::Unknown;
use super::meta::UserAddrMeta;
use super::normalizer::NormalizedAddrs;


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
        )
        .into())
    }

    let path = apk.join(elf);
    Ok(path)
}


pub(crate) fn normalize_elf_offset_with_parser(
    offset: u64,
    parser: &ElfParser,
) -> Result<Option<Addr>> {
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
    let file_off = virt_addr - entry.range.start + entry.offset;
    let parser = ElfParser::open(&entry.path.maps_file)
        .with_context(|| format!("failed to open map file {}", entry.path.maps_file.display()))?;
    let addr = normalize_elf_offset_with_parser(file_off, &parser)?.ok_or_invalid_input(|| {
        format!(
            "failed to find ELF segment in {} that contains file offset {:#x}",
            entry.path.symbolic_path.display(),
            entry.offset,
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
    let file_off = virt_addr - entry.range.start + entry.offset;
    // An APK is nothing but a fancy zip archive.
    let apk = zip::Archive::open(&entry.path.maps_file)?;

    // Find the APK entry covering the calculated file offset.
    for apk_entry in apk.entries() {
        let apk_entry = apk_entry?;
        let bounds = apk_entry.data_offset..apk_entry.data_offset + apk_entry.data.len() as u64;

        if bounds.contains(&file_off) {
            let mmap = apk
                .mmap()
                .constrain(bounds.clone())
                .ok_or_invalid_input(|| {
                    format!(
                        "invalid APK entry data bounds ({bounds:?}) in {}",
                        entry.path.symbolic_path.display()
                    )
                })?;
            let parser = ElfParser::from_mmap(mmap);
            let elf_off = file_off - apk_entry.data_offset;
            if let Some(addr) = normalize_elf_offset_with_parser(elf_off, &parser)? {
                return Ok((addr, apk_entry.path.to_path_buf(), parser))
            }
            break
        }
    }

    Err(Error::new(
        ErrorKind::InvalidInput,
        format!(
            "failed to find ELF entry in {} that contains file offset {:#x}",
            entry.path.symbolic_path.display(),
            file_off,
        ),
    )
    .into())
}


/// A type representing normalized user addresses.
pub type NormalizedUserAddrs = NormalizedAddrs<UserAddrMeta>;

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
    fn new(addr_cnt: usize) -> Self {
        Self {
            normalized: NormalizedUserAddrs {
                addrs: Vec::with_capacity(addr_cnt),
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
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"))))]
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
            )
            .into())
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
pub(super) fn normalize_user_addrs_sorted_impl<A>(
    addrs: A,
    pid: Pid,
    read_build_ids: bool,
) -> Result<NormalizedUserAddrs>
where
    A: ExactSizeIterator<Item = Addr> + Clone,
{
    let addrs_cnt = addrs.len();
    let entries = maps::parse(pid)?;

    if read_build_ids {
        let handler = NormalizationHandler::<DefaultBuildIdReader>::new(addrs_cnt);
        let handler = normalize_sorted_user_addrs_with_entries(addrs, entries, handler)?;
        debug_assert_eq!(handler.normalized.addrs.len(), addrs_cnt);
        Ok(handler.normalized)
    } else {
        let handler = NormalizationHandler::<NoBuildIdReader>::new(addrs_cnt);
        let handler = normalize_sorted_user_addrs_with_entries(addrs, entries, handler)?;
        debug_assert_eq!(handler.normalized.addrs.len(), addrs_cnt);
        Ok(handler.normalized)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf).unwrap();
        assert_eq!(path, Path::new("/root/test.apk!/subdir/libc.so"));
    }

    /// Check that we correctly handle normalization of an address not
    /// in any executable segment.
    #[test]
    fn user_address_normalization_static_maps() {
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
            let normalized = normalize_sorted_user_addrs_with_entries(
                addrs.as_slice().iter().copied(),
                entries,
                handler,
            )
            .unwrap()
            .normalized;
            assert_eq!(normalized.addrs.len(), 1);
            assert_eq!(normalized.meta.len(), 1);
            assert_eq!(normalized.meta[0], Unknown::default().into());
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

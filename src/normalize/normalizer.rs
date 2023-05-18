use std::collections::HashMap;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::path::Path;
use std::path::PathBuf;

use crate::elf;
use crate::elf::types::Elf64_Nhdr;
use crate::elf::ElfParser;
use crate::log::warn;
use crate::maps;
use crate::maps::PathMapsEntry;
use crate::util;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Pid;

use super::meta::Binary;
use super::meta::Unknown;
use super::meta::UserAddrMeta;


/// A typedef for functions reading build IDs.
type BuildIdFn = dyn Fn(&Path) -> Result<Option<Vec<u8>>>;


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


/// Attempt to read an ELF binary's build ID.
// TODO: Currently look up is always performed based on section name, but there
//       is also the possibility of iterating notes and checking checking
//       Elf64_Nhdr.n_type for NT_GNU_BUILD_ID, specifically.
fn read_build_id(path: &Path) -> Result<Option<Vec<u8>>> {
    let build_id_section = ".note.gnu.build-id";
    let file = File::open(path)?;
    let parser = ElfParser::open_file(file)?;

    // The build ID is contained in the `.note.gnu.build-id` section. See
    // elf(5).
    if let Ok(idx) = parser.find_section(build_id_section) {
        // SANITY: We just found the index so the section should always be
        //         found.
        let shdr = parser.section_headers()?.get(idx).unwrap();
        if shdr.sh_type != elf::types::SHT_NOTE {
            warn!(
                "build ID section {build_id_section} of {} is of unsupported type ({})",
                path.display(),
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
}


pub(crate) trait Handler {
    /// Handle an unknown address.
    fn handle_unknown_addr(&mut self, addr: Addr) -> Result<()>;

    /// Handle an address residing in the provided [`PathMapsEntry`].
    fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()>;
}


struct NormalizationHandler {
    /// The normalized user addresses we are building up.
    normalized: NormalizedUserAddrs,
    /// Lookup table from path (as used in each proc maps entry) to index into
    /// `normalized.meta`.
    meta_lookup: HashMap<PathBuf, usize>,
    /// The index of the `Unknown` entry in `meta_lookup`, used for all unknown
    /// addresses.
    unknown_idx: Option<usize>,
    /// The function used for retrieving build IDs.
    get_build_id: &'static BuildIdFn,
}

impl NormalizationHandler {
    /// Instantiate a new `NormalizationHandler` object.
    fn new(addr_count: usize, get_build_id: &'static BuildIdFn) -> Self {
        Self {
            normalized: NormalizedUserAddrs {
                addrs: Vec::with_capacity(addr_count),
                meta: Vec::new(),
            },
            meta_lookup: HashMap::<PathBuf, usize>::new(),
            unknown_idx: None,
            get_build_id,
        }
    }
}

impl Handler for NormalizationHandler {
    fn handle_unknown_addr(&mut self, addr: Addr) -> Result<()> {
        self.unknown_idx = self.normalized.add_unknown_addr(addr, self.unknown_idx);
        Ok(())
    }

    fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
        let meta_idx = if let Some(meta_idx) = self.meta_lookup.get(&entry.path.symbolic_path) {
            *meta_idx
        } else {
            let binary = Binary {
                path: entry.path.symbolic_path.to_path_buf(),
                build_id: (self.get_build_id)(&entry.path.maps_file)?,
                _non_exhaustive: (),
            };

            let meta_idx = self.normalized.meta.len();
            let () = self.normalized.meta.push(UserAddrMeta::Binary(binary));
            let _ref = self
                .meta_lookup
                .insert(entry.path.symbolic_path.to_path_buf(), meta_idx);
            meta_idx
        };

        let normalized_addr = normalize_elf_addr(addr, entry)?;
        let () = self.normalized.addrs.push((normalized_addr, meta_idx));
        Ok(())
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
    /// The process' ID should be provided in `pid`. To normalize addresses of the
    /// calling processes, `0` can be provided as a sentinel for the current
    /// process' ID.
    ///
    /// Normalized addresses are reported in the exact same order in which the
    /// non-normalized ones were provided.
    fn normalize_user_addrs_sorted_impl<A>(&self, addrs: A, pid: Pid) -> Result<NormalizedUserAddrs>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
    {
        let entries = maps::parse(pid)?;
        let handler = NormalizationHandler::new(addrs.len(), &read_build_id);
        let handler = normalize_sorted_user_addrs_with_entries(addrs, entries, handler)?;
        Ok(handler.normalized)
    }

    /// Normalize `addresses` belonging to a process.
    ///
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
    /// The process' ID should be provided in `pid`. To normalize addresses of the
    /// calling processes, `0` can be provided as a sentinel for the current
    /// process' ID.
    ///
    /// Normalized addresses are reported in the exact same order in which the
    /// non-normalized ones were provided.
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
    /// [`Normalizer::normalize_user_addrs_sorted`], the provided
    /// `addrs` array does not have to be sorted, but otherwise the
    /// functions behave identically.
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


    /// Check that we can read a binary's build ID.
    #[test]
    fn build_id_reading() {
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");

        let build_id = read_build_id(&elf).unwrap().unwrap();
        // The file contains a sha1 build ID, which is always 40 hex digits.
        assert_eq!(build_id.len(), 20, "'{build_id:?}'");

        // The shared object is explicitly built without build ID.
        let elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");
        let build_id = read_build_id(&elf).unwrap();
        assert_eq!(build_id, None);
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
            build_id_reading as Addr,
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
            .binary()
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
        let symbols = elf_parser.find_addr("the_answer", &opts).unwrap();
        // There is only one symbol with this address in there.
        assert_eq!(symbols.len(), 1);
        let symbol = symbols.first().unwrap();

        let the_answer_addr = unsafe { mmap.as_ptr().add(symbol.addr) };
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
        assert_eq!(norm_addr.0, symbol.addr);
        let meta = &norm_addrs.meta[norm_addr.1];
        let so_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let expected_binary = Binary {
            build_id: Some(read_build_id(&so_path).unwrap().unwrap()),
            path: so_path,
            _non_exhaustive: (),
        };
        assert_eq!(meta, &UserAddrMeta::Binary(expected_binary));
    }

    /// Check that we correctly handle normalization of an address not
    /// in any executable segment.
    #[test]
    fn user_address_normalization_static_maps() {
        fn read_no_build_id(_path: &Path) -> Result<Option<Vec<u8>>> {
            Ok(None)
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

            let handler = NormalizationHandler::new(addrs.len(), &read_no_build_id);
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

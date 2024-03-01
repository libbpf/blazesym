use crate::insert_map::InsertMap;
use crate::maps;
use crate::util;
use crate::Addr;
use crate::Pid;
use crate::Result;

use super::buildid::DefaultBuildIdReader;
use super::buildid::NoBuildIdReader;
use super::user;
use super::user::normalize_sorted_user_addrs_with_entries;
use super::user::UserOutput;


/// A type capturing normalized outputs along with captured meta data.
///
/// This type enables "remote" symbolization. That is to say, it represents the
/// input necessary for addresses to be symbolized on a system other than where
/// they were recorded.
#[derive(Clone, Debug)]
pub struct Output<M> {
    /// Outputs along with an index into `meta` for retrieval of the
    /// corresponding meta information.
    ///
    /// The output is a file offset when normalization was successful and the
    /// unnormalized input address otherwise. Normalization errors are indicated
    /// by an index referencing a [`Unknown`][crate::normalize::Unknown] object.
    ///
    /// A file offset is one as it would appear in a binary or debug symbol
    /// file, i.e., one excluding any relocations. The data reported here can be
    /// used with the
    /// [`symbolize::Input::FileOffset`][crate::symbolize::Input::FileOffset]
    /// variant.
    pub outputs: Vec<(u64, usize)>,
    /// Meta information about the normalized outputs.
    pub meta: Vec<M>,
}


/// A builder for configurable construction of [`Normalizer`] objects.
///
/// By default reading of build IDs is enabled, while caching of
/// `/proc/<pid>/maps` entries is disabled.
#[derive(Clone, Debug)]
pub struct Builder {
    /// Whether or not to cache `/proc/<pid>/maps` contents.
    ///
    /// Setting this flag to `true` is not generally recommended, because it
    /// could result in addresses corresponding to mappings added after caching
    /// may not be normalized successfully, as there is no reasonable way of
    /// detecting staleness.
    cache_maps: bool,
    /// Whether to read and report build IDs as part of the normalization
    /// process.
    build_ids: bool,
}

impl Builder {
    /// Enable/disable the caching of `/proc/<pid>/maps` entries.
    pub fn enable_maps_caching(mut self, enable: bool) -> Builder {
        self.cache_maps = enable;
        self
    }

    /// Enable/disable the reading of build IDs.
    pub fn enable_build_ids(mut self, enable: bool) -> Builder {
        self.build_ids = enable;
        self
    }

    /// Create the [`Normalizer`] object.
    pub fn build(self) -> Normalizer {
        let Builder {
            cache_maps,
            build_ids,
        } = self;

        Normalizer {
            cache_maps,
            build_ids,
            cached_entries: InsertMap::new(),
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            cache_maps: false,
            build_ids: true,
        }
    }
}


/// A normalizer for addresses.
///
/// Address normalization is the process of taking virtual absolute
/// addresses as they are seen by, say, a process (which include
/// relocation and process specific layout randomizations, among other
/// things) and converting them to "normalized" virtual addresses as
/// they are present in, say, an ELF binary or a DWARF debug info file,
/// and one would be able to see them using tools such as readelf(1).
///
/// If caching of `/proc/<pid>/maps` is enabled, an instance of this type is the
/// unit at which caching happens. If you are normalizing address in a large
/// number of processes over time, you may want to consider creating a new
/// `Normalizer` instance regularly to free up cached data.
#[derive(Debug, Default)]
pub struct Normalizer {
    /// Whether or not to cache `/proc/<pid>/maps` contents.
    ///
    /// Setting this flag to `true` is not generally recommended, because it
    /// could result in addresses corresponding to mappings added after caching
    /// may not be normalized successfully, as there is no reasonable way of
    /// detecting staleness.
    cache_maps: bool,
    /// Flag indicating whether or not to read build IDs as part of the
    /// normalization process.
    build_ids: bool,
    /// If `cache_maps` is `true`, the cached parsed
    /// [`MapsEntry`][maps::MapsEntry] objects.
    cached_entries: InsertMap<Pid, Box<[maps::MapsEntry]>>,
}

impl Normalizer {
    /// Create a new [`Normalizer`].
    ///
    /// This method is just a short hand for instantiating a `Normalizer` from
    /// the default [`Builder`].
    #[inline]
    pub fn new() -> Self {
        Builder::default().build()
    }

    /// Retrieve a [`Builder`] object for configurable construction of a
    /// [`Normalizer`].
    #[inline]
    pub fn builder() -> Builder {
        Builder::default()
    }

    fn normalize_user_addrs_impl<A, E, M>(&self, addrs: A, entries: E) -> Result<UserOutput>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
        E: Iterator<Item = Result<M>>,
        M: AsRef<maps::MapsEntry>,
    {
        let addrs_cnt = addrs.len();
        if self.build_ids {
            let mut handler = user::NormalizationHandler::<DefaultBuildIdReader>::new(addrs_cnt);
            let () = normalize_sorted_user_addrs_with_entries(addrs, entries, &mut handler, ())?;
            debug_assert_eq!(handler.normalized.outputs.len(), addrs_cnt);
            Ok(handler.normalized)
        } else {
            let mut handler = user::NormalizationHandler::<NoBuildIdReader>::new(addrs_cnt);
            let () = normalize_sorted_user_addrs_with_entries(addrs, entries, &mut handler, ())?;
            debug_assert_eq!(handler.normalized.outputs.len(), addrs_cnt);
            Ok(handler.normalized)
        }
    }

    /// Normalize all `addrs` in a given process to the corresponding file
    /// offsets, which are suitable for later symbolization. The `addrs`
    /// array has to be sorted in ascending order or an error will be
    /// returned.
    ///
    /// Unknown addresses are not normalized. They are reported as
    /// [`Unknown`] meta entries in the returned [`UserOutput`]
    /// object. The cause of an address to be unknown (and, hence, not
    /// normalized), could have a few reasons, including, but not limited
    /// to:
    /// - user error (if a bogus address was provided)
    /// - they belonged to an ELF object that has been unmapped since the
    ///   address was captured
    ///
    /// The process' ID should be provided in `pid`.
    ///
    /// File offsets are reported in the exact same order in which the
    /// non-normalized addresses were provided.
    fn normalize_user_addrs_iter<A>(&self, addrs: A, pid: Pid) -> Result<UserOutput>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
    {
        if !self.cache_maps {
            let entries = maps::parse_filtered(pid)?;
            self.normalize_user_addrs_impl(addrs, entries)
        } else {
            let parsed = self.cached_entries.get_or_try_insert(pid, || {
                // If we use the cached maps entries but don't have anything
                // cached yet, then just parse the file eagerly and take it from
                // there.
                let parsed = maps::parse_filtered(pid)?
                    .collect::<Result<Vec<_>>>()?
                    .into_boxed_slice();
                Result::<Box<[maps::MapsEntry]>>::Ok(parsed)
            })?;

            let entries = parsed.iter().map(Ok);
            self.normalize_user_addrs_impl(addrs, entries)
        }
    }

    /// Normalize addresses belonging to a process.
    ///
    /// Normalize all `addrs` in a given process. The `addrs` array has
    /// to be sorted in ascending order or an error will be returned. By
    /// providing a pre-sorted array the library does not have to sort
    /// internally, which will result in quicker normalization. If you
    /// don't have sorted addresses, use
    /// [`Normalizer::normalize_user_addrs`] instead.
    ///
    /// Unknown addresses are not normalized. They are reported as
    /// [`Unknown`][crate::normalize::Unknown] meta entries in the returned
    /// [`UserOutput`] object. The cause of an address to be unknown (and,
    /// hence, not normalized), could be manifold, including, but not limited
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
    pub fn normalize_user_addrs_sorted(&self, pid: Pid, addrs: &[Addr]) -> Result<UserOutput> {
        self.normalize_user_addrs_iter(addrs.iter().copied(), pid)
    }


    /// Normalize addresses belonging to a process.
    ///
    /// Normalize all `addrs` in a given process. Contrary to
    /// [`Normalizer::normalize_user_addrs_sorted`], the provided `addrs` array
    /// does not have to be sorted, but otherwise the functions behave
    /// identically. If you do happen to know that `addrs` is sorted, using
    /// [`Normalizer::normalize_user_addrs_sorted`] instead will result in
    /// slightly faster normalization.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self)))]
    pub fn normalize_user_addrs(&self, pid: Pid, addrs: &[Addr]) -> Result<UserOutput> {
        util::with_ordered_elems(
            addrs,
            |normalized: &mut UserOutput| normalized.outputs.as_mut_slice(),
            |sorted_addrs| self.normalize_user_addrs_iter(sorted_addrs, pid),
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::transmute;
    use std::path::Path;

    use test_log::test;

    use crate::elf::ElfParser;
    use crate::inspect::FindAddrOpts;
    use crate::mmap::Mmap;
    use crate::normalize::buildid::read_elf_build_id;
    use crate::normalize::Apk;
    use crate::normalize::Elf;
    use crate::normalize::Unknown;
    use crate::normalize::UserMeta;
    use crate::symbolize;
    use crate::symbolize::Symbolizer;
    use crate::SymType;


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
            .normalize_user_addrs_sorted(Pid::Slf, addrs.as_slice())
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
        let normalized = normalizer
            .normalize_user_addrs_sorted(Pid::Slf, addrs.as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 2);
        assert_eq!(normalized.meta.len(), 1);
        assert_eq!(normalized.meta[0], Unknown::default().into());
        assert_eq!(normalized.outputs[0].1, 0);
        assert_eq!(normalized.outputs[1].1, 0);
    }

    /// Check that we can normalize user addresses.
    #[test]
    fn user_address_normalization() {
        fn test(normalizer: &Normalizer) {
            let addrs = [
                libc::__errno_location as Addr,
                libc::dlopen as Addr,
                libc::fopen as Addr,
                user_address_normalization_unknown as Addr,
                user_address_normalization as Addr,
                Mmap::map as Addr,
            ];

            let (errno_idx, _) = addrs
                .iter()
                .enumerate()
                .find(|(_idx, addr)| **addr == libc::__errno_location as Addr)
                .unwrap();

            let normalized = normalizer
                .normalize_user_addrs(Pid::Slf, addrs.as_slice())
                .unwrap();
            assert_eq!(normalized.outputs.len(), 6);

            let outputs = &normalized.outputs;
            let meta = &normalized.meta;
            assert_eq!(meta.len(), 2);

            let errno_meta_idx = outputs[errno_idx].1;
            assert!(meta[errno_meta_idx]
                .elf()
                .unwrap()
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("libc.so"));
        }

        let normalizer = Normalizer::new();
        test(&normalizer);

        let normalizer = Normalizer::builder().enable_maps_caching(true).build();
        test(&normalizer);
        test(&normalizer);
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

        let the_answer_addr = unsafe { mmap.as_ptr().add(sym.addr as usize) };
        // Now just double check that everything worked out and the function
        // is actually where it was meant to be.
        let the_answer_fn =
            unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
        let answer = the_answer_fn();
        assert_eq!(answer, 42);

        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs_sorted(Pid::Slf, [the_answer_addr as Addr].as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let output = normalized.outputs[0];
        assert_eq!(output.0, sym.addr);
        let meta = &normalized.meta[output.1];
        let so_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let expected_elf = Elf {
            build_id: Some(read_elf_build_id(&so_path).unwrap().unwrap()),
            path: so_path,
            _non_exhaustive: (),
        };
        assert_eq!(meta, &UserMeta::Elf(expected_elf));
    }

    /// Check that we can normalize addresses in our own shared object inside a
    /// zip archive.
    #[test]
    fn normalize_custom_so_in_zip() {
        use crate::zip;

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
                .constrain(so.data_offset..so.data_offset + so.data.len() as u64)
                .unwrap();

            // Look up the address of the `the_answer` function inside of the shared
            // object.
            let elf_parser = ElfParser::from_mmap(elf_mmap.clone());
            let opts = FindAddrOpts {
                sym_type: SymType::Function,
                offset_in_file: true,
            };
            let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
            // There is only one symbol with this address in there.
            assert_eq!(syms.len(), 1);
            let sym = syms.first().unwrap();

            let the_answer_addr = unsafe { elf_mmap.as_ptr().add(sym.addr as usize) };
            // Now just double check that everything worked out and the function
            // is actually where it was meant to be.
            let the_answer_fn =
                unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
            let answer = the_answer_fn();
            assert_eq!(answer, 42);

            let normalizer = Normalizer::new();
            let normalized = normalizer
                .normalize_user_addrs_sorted(Pid::Slf, [the_answer_addr as Addr].as_slice())
                .unwrap();
            assert_eq!(normalized.outputs.len(), 1);
            assert_eq!(normalized.meta.len(), 1);

            let expected_offset =
                so.data_offset + elf_parser.find_file_offset(sym.addr).unwrap().unwrap();
            let output = normalized.outputs[0];
            assert_eq!(output.0, expected_offset);
            let meta = &normalized.meta[output.1];
            let expected = Apk {
                path: test_zip.clone(),
                _non_exhaustive: (),
            };
            assert_eq!(meta, &UserMeta::Apk(expected));

            // Also symbolize the normalization output.
            let apk = symbolize::Apk::new(test_zip);
            let src = symbolize::Source::Apk(apk);
            let symbolizer = Symbolizer::new();
            let result = symbolizer
                .symbolize_single(&src, symbolize::Input::FileOffset(output.0))
                .unwrap()
                .into_sym()
                .unwrap();

            assert_eq!(result.name, "the_answer");

            let results = symbolizer
                .symbolize(&src, symbolize::Input::FileOffset(&[output.0]))
                .unwrap();
            assert_eq!(results.len(), 1);

            let sym = results[0].as_sym().unwrap();
            assert_eq!(sym.name, "the_answer");
        }

        test("libtest-so.so");
        test("libtest-so-no-separate-code.so");
    }
}

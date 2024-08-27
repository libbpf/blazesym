use std::fs::File;

use crate::file_cache::FileCache;
use crate::insert_map::InsertMap;
use crate::maps;
use crate::normalize::buildid::BuildIdReader;
use crate::normalize::buildid::CachingBuildIdReader;
use crate::util;
#[cfg(feature = "tracing")]
use crate::util::Hexify;
use crate::Addr;
use crate::ErrorExt as _;
use crate::Pid;
use crate::Result;

use super::buildid::BuildId;
use super::buildid::DefaultBuildIdReader;
use super::buildid::NoBuildIdReader;
use super::ioctl::query_procmap;
use super::user;
use super::user::normalize_sorted_user_addrs_with_entries;
use super::user::UserOutput;
use super::NormalizeOpts;


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
/// By default `/proc/<pid>/maps` contents are parsed to query available
/// VMA ranges (instead of using the `PROCMAP_QUERY` ioctl). Reading of
/// build IDs is enabled, but they are not being cached. The caching of
/// VMA ranges is also disabled.
#[derive(Clone, Debug)]
pub struct Builder {
    /// See [`Builder::enable_procmap_query`].
    use_procmap_query: bool,
    /// See [`Builder::enable_vma_caching`].
    cache_vmas: bool,
    /// See [`Builder::enable_build_ids`].
    build_ids: bool,
    /// See [`Builder::enable_build_id_caching`].
    cache_build_ids: bool,
}

impl Builder {
    /// Enable/disable the usage of the `PROCMAP_QUERY` ioctl instead of
    /// parsing `/proc/<pid>/maps` for getting available VMA ranges.
    ///
    /// Refer to
    /// [`helper::is_procmap_query_supported`][crate::helper::is_procmap_query_supported]
    /// as a way to check whether your system supports this
    /// functionality.
    ///
    /// # Notes
    ///
    /// Support for this ioctl is only present in very recent kernels
    /// (likely: 6.11+). See <https://lwn.net/Articles/979931/> for
    /// details.
    ///
    /// Furthermore, the ioctl will also be used for retrieving build
    /// IDs (if enabled). Build ID reading logic in the kernel is known
    /// to be incomplete, with a fix slated to be included only with
    /// 6.12.
    pub fn enable_procmap_query(mut self, enable: bool) -> Builder {
        self.use_procmap_query = enable;
        self
    }

    /// Enable/disable caching VMA ranges and meta data (excluding build
    /// IDs).
    ///
    /// Setting this flag to `true` is not generally recommended, because it
    /// could result in addresses corresponding to mappings added after caching
    /// may not be normalized successfully, as there is no reasonable way of
    /// detecting staleness.
    ///
    /// Please note than if the `PROCMAP_QUERY` ioctl is being used, VMA
    /// caching implies build ID caching as well.
    pub fn enable_vma_caching(mut self, enable: bool) -> Builder {
        self.cache_vmas = enable;
        self
    }

    /// Enable/disable the reading of build IDs as appropriate.
    ///
    /// Note that build ID read failures will be swallowed without
    /// failing the normalization operation.
    pub fn enable_build_ids(mut self, enable: bool) -> Builder {
        self.build_ids = enable;
        self
    }

    /// Enable/disable the caching of build IDs.
    ///
    /// # Notes
    /// This property only has a meaning if reading of build IDs is
    /// enabled as well and it is not auto-enabled by this method.
    pub fn enable_build_id_caching(mut self, enable: bool) -> Builder {
        self.cache_build_ids = enable;
        self
    }

    /// Create the [`Normalizer`] object.
    pub fn build(self) -> Normalizer {
        let Builder {
            use_procmap_query,
            cache_vmas,
            build_ids,
            cache_build_ids,
        } = self;

        Normalizer {
            use_procmap_query,
            cache_vmas,
            build_ids,
            cache_build_ids: build_ids && cache_build_ids,
            cached_entries: InsertMap::new(),
            cached_build_ids: FileCache::default(),
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            use_procmap_query: false,
            cache_vmas: false,
            build_ids: true,
            cache_build_ids: false,
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
/// If caching of data is enabled, an instance of this type is the unit
/// at which caching happens. If you are normalizing address in a large
/// number of processes or involving a larger number of binaries with
/// build IDs over time, you may want to consider creating a new
/// `Normalizer` instance regularly to free up cached data.
#[derive(Debug, Default)]
pub struct Normalizer {
    /// See [`Builder::enable_procmap_query`].
    use_procmap_query: bool,
    /// See [`Builder::enable_maps_caching`].
    cache_vmas: bool,
    /// See [`Builder::enable_build_ids`].
    build_ids: bool,
    /// See [`Builder::enable_build_id_caching`].
    cache_build_ids: bool,
    /// If `cache_vmas` is `true`, the cached parsed
    /// [`MapsEntry`][maps::MapsEntry] objects.
    cached_entries: InsertMap<Pid, Box<[maps::MapsEntry]>>,
    /// A cache of build IDs.
    cached_build_ids: FileCache<Option<BuildId<'static>>>,
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

    fn normalize_user_addrs_impl<A, E, M>(
        &self,
        addrs: A,
        entries: E,
        map_files: bool,
    ) -> Result<UserOutput<'_>>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
        E: FnMut(Addr) -> Option<Result<M>>,
        M: AsRef<maps::MapsEntry>,
    {
        let caching_reader;
        let addrs_cnt = addrs.len();
        let reader = if self.build_ids {
            if self.cache_build_ids {
                caching_reader = CachingBuildIdReader::new(&self.cached_build_ids);
                &caching_reader as &dyn BuildIdReader
            } else {
                &DefaultBuildIdReader as &dyn BuildIdReader
            }
        } else {
            // Build ID caching always implies reading of build IDs to
            // begin with.
            debug_assert!(!self.cache_build_ids);
            &NoBuildIdReader as &dyn BuildIdReader
        };

        let mut handler = user::NormalizationHandler::new(reader, addrs_cnt, map_files);
        let () = normalize_sorted_user_addrs_with_entries(addrs, entries, &mut handler)?;
        debug_assert_eq!(handler.normalized.outputs.len(), addrs_cnt);
        Ok(handler.normalized)
    }

    fn normalize_user_addrs_iter<A>(
        &self,
        addrs: A,
        pid: Pid,
        map_files: bool,
    ) -> Result<UserOutput>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
    {
        if self.use_procmap_query {
            let path = format!("/proc/{pid}/maps");
            let file = File::open(&path)
                .with_context(|| format!("failed to open `{path}` for reading"))?;

            if !self.cache_vmas {
                let entries =
                    move |addr| query_procmap(&file, pid, addr, self.build_ids).transpose();
                self.normalize_user_addrs_impl(addrs, entries, map_files)
            } else {
                let entries = self.cached_entries.get_or_try_insert(pid, || {
                    let mut entries = Vec::new();
                    let mut next_addr = 0;
                    while let Some(entry) = query_procmap(&file, pid, next_addr, self.build_ids)? {
                        next_addr = entry.range.end;
                        if maps::filter_relevant(&entry) {
                            let () = entries.push(entry);
                        }
                    }
                    Ok(entries.into_boxed_slice())
                })?;

                let mut entry_iter = entries.iter().map(Ok);
                let entries = |_addr| entry_iter.next();
                self.normalize_user_addrs_impl(addrs, entries, map_files)
            }
        } else {
            if !self.cache_vmas {
                let mut entry_iter = maps::parse_filtered(pid)?;
                let entries = |_addr| entry_iter.next();
                self.normalize_user_addrs_impl(addrs, entries, map_files)
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

                let mut entry_iter = parsed.iter().map(Ok);
                let entries = |_addr| entry_iter.next();
                self.normalize_user_addrs_impl(addrs, entries, map_files)
            }
        }
    }

    /// Normalize addresses belonging to a process.
    ///
    /// Normalize all `addrs` in a given process to their corresponding
    /// file offsets, which are suitable for later symbolization.
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
    /// Normalized outputs are reported in the exact same order (and in
    /// equal amount) in which the non-normalized ones were provided.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(pid = ?pid, addrs = ?Hexify(addrs))))]
    pub fn normalize_user_addrs_opts(
        &self,
        pid: Pid,
        addrs: &[Addr],
        opts: &NormalizeOpts,
    ) -> Result<UserOutput> {
        let NormalizeOpts {
            sorted_addrs,
            map_files,
            _non_exhaustive: (),
        } = *opts;

        if sorted_addrs {
            self.normalize_user_addrs_iter(addrs.iter().copied(), pid, map_files)
        } else {
            util::with_ordered_elems(
                addrs,
                |normalized: &mut UserOutput| normalized.outputs.as_mut_slice(),
                |sorted_addrs| self.normalize_user_addrs_iter(sorted_addrs, pid, map_files),
            )
        }
    }

    /// Normalize addresses belonging to a process.
    ///
    /// A convenience wrapper around [`Normalizer::normalize_user_addrs_opts`][]
    /// that uses the default normalization options.
    pub fn normalize_user_addrs(&self, pid: Pid, addrs: &[Addr]) -> Result<UserOutput> {
        self.normalize_user_addrs_opts(pid, addrs, &NormalizeOpts::default())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::copy;
    use std::path::Path;

    use tempfile::tempdir;

    use test_log::test;

    use crate::mmap::Mmap;
    use crate::normalize::buildid::read_elf_build_id;
    use crate::normalize::Apk;
    use crate::normalize::Elf;
    use crate::normalize::Reason;
    use crate::normalize::Unknown;
    use crate::normalize::UserMeta;
    use crate::symbolize;
    use crate::symbolize::Symbolizer;
    use crate::test_helper::find_the_answer_fn;
    use crate::zip;


    /// Check that we detect unsorted input addresses.
    #[test]
    fn user_address_normalization_unsorted() {
        let mut addrs = [
            libc::atexit as Addr,
            libc::chdir as Addr,
            libc::fopen as Addr,
        ];
        let () = addrs.sort();
        let () = addrs.swap(0, 1);

        let opts = NormalizeOpts {
            sorted_addrs: true,
            ..Default::default()
        };
        let normalizer = Normalizer::new();
        let err = normalizer
            .normalize_user_addrs_opts(Pid::Slf, addrs.as_slice(), &opts)
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
            .normalize_user_addrs(Pid::Slf, addrs.as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 2);
        assert_eq!(normalized.meta.len(), 1);
        assert_eq!(normalized.meta[0], Unknown::new(Reason::Unmapped).into());
        assert_eq!(normalized.outputs[0].1, 0);
        assert_eq!(normalized.outputs[1].1, 0);
    }

    /// Check that we can normalize user addresses.
    #[cfg(not(windows))]
    // `libc` on Arm doesn't have `__errno_location`.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
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
                .as_elf()
                .unwrap()
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("libc.so"));
        }

        let normalizer = Normalizer::new();
        test(&normalizer);

        let normalizer = Normalizer::builder().enable_vma_caching(true).build();
        test(&normalizer);
        test(&normalizer);
    }

    /// Check that we can normalize user addresses in our own shared object.
    #[test]
    fn user_address_normalization_custom_so() {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");

        let mmap = Mmap::builder().exec().open(&test_so).unwrap();
        let (sym, the_answer_addr) = find_the_answer_fn(&mmap);

        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs(Pid::Slf, [the_answer_addr as Addr].as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let output = normalized.outputs[0];
        assert_eq!(output.0, sym.addr);
        let meta = &normalized.meta[output.1];
        let expected_elf = Elf {
            build_id: Some(read_elf_build_id(&test_so).unwrap().unwrap()),
            path: test_so.clone(),
            _non_exhaustive: (),
        };
        assert_eq!(meta, &UserMeta::Elf(expected_elf));
    }

    fn test_user_address_normalization_deleted_so(use_procmap_query: bool) {
        fn test(
            use_procmap_query: bool,
            cache_vmas: bool,
            cache_build_ids: bool,
            use_map_files: bool,
        ) {
            let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("libtest-so.so");
            let dir = tempdir().unwrap();
            let tmp_so = dir.path().join("libtest-so.so");
            let _count = copy(&test_so, &tmp_so).unwrap();

            let mmap = Mmap::builder().exec().open(&tmp_so).unwrap();
            let (sym, the_answer_addr) = find_the_answer_fn(&mmap);

            // Remove the temporary directory and with it the mapped shared
            // object.
            let () = drop(dir);

            let opts = NormalizeOpts {
                sorted_addrs: false,
                map_files: use_map_files,
                ..Default::default()
            };
            let normalizer = Normalizer::builder()
                .enable_procmap_query(use_procmap_query)
                .enable_vma_caching(cache_vmas)
                .enable_build_id_caching(cache_build_ids)
                .build();
            let normalized = normalizer
                .normalize_user_addrs_opts(Pid::Slf, [the_answer_addr as Addr].as_slice(), &opts)
                .unwrap();
            assert_eq!(normalized.outputs.len(), 1);
            assert_eq!(normalized.meta.len(), 1);

            let output = normalized.outputs[0];
            assert_eq!(output.0, sym.addr);
            let meta = &normalized.meta[output.1].as_elf().unwrap();
            assert_eq!(
                meta.build_id,
                Some(read_elf_build_id(&test_so).unwrap().unwrap())
            );
        }

        for cache_build_ids in [true, false] {
            for cache_vmas in [true, false] {
                for use_map_files in [true, false] {
                    let () = test(
                        use_procmap_query,
                        cache_build_ids,
                        cache_vmas,
                        use_map_files,
                    );
                }
            }
        }
    }

    /// Check that we can normalize user addresses in a shared object
    /// that has been deleted already (but is still mapped) without
    /// errors.
    #[test]
    fn user_address_normalization_deleted_so_proc_maps() {
        test_user_address_normalization_deleted_so(false)
    }

    /// Check that we can normalize user addresses in a shared object
    /// that has been deleted already (but is still mapped) without
    /// errors.
    #[test]
    #[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
    fn user_address_normalization_deleted_so_ioctl() {
        test_user_address_normalization_deleted_so(true)
    }

    /// Check that we can normalize addresses in our own shared object inside a
    /// zip archive.
    #[test]
    fn normalize_custom_so_in_zip() {
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
            let (sym, the_answer_addr) = find_the_answer_fn(&elf_mmap);

            let opts = NormalizeOpts {
                sorted_addrs: true,
                ..Default::default()
            };
            let normalizer = Normalizer::new();
            let normalized = normalizer
                .normalize_user_addrs_opts(Pid::Slf, [the_answer_addr as Addr].as_slice(), &opts)
                .unwrap();
            assert_eq!(normalized.outputs.len(), 1);
            assert_eq!(normalized.meta.len(), 1);

            let expected_offset = so.data_offset + sym.file_offset.unwrap();
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

    /// Make sure that when using the `map_files` normalization option,
    /// we never end up reporting a path referencing "self".
    #[test]
    fn normalize_no_self_vma_path_reporting() {
        let opts = NormalizeOpts {
            sorted_addrs: true,
            map_files: true,
            ..Default::default()
        };
        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs_opts(
                Pid::Slf,
                [normalize_no_self_vma_path_reporting as Addr].as_slice(),
                &opts,
            )
            .unwrap();

        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);
        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        let elf = meta.as_elf().unwrap();
        assert!(!elf.path.to_string_lossy().contains("self"), "{elf:?}");
    }
}

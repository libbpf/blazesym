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
/// things) and converting them to file offsets. This is typically a
/// very fast running operation. The file offsets can subsequently be
/// used as symbolization input.
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
    /// See [`Builder::enable_vma_caching`].
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
                    let parsed = maps::parse_filtered(pid)?.collect::<Result<Box<_>>>()?;
                    Ok(parsed)
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
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(pid = ?pid, addrs = ?Hexify(addrs)), err))]
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

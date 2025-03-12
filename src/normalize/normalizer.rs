use std::borrow::Cow;
use std::fs::File;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "apk")]
use crate::apk::create_apk_elf_path;
use crate::elf::ElfParser;
use crate::file_cache::FileCache;
use crate::insert_map::InsertMap;
use crate::maps;
use crate::util;
#[cfg(feature = "tracing")]
use crate::util::Hexify;
#[cfg(feature = "apk")]
use crate::zip;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Mmap;
use crate::Pid;
use crate::Result;

use super::buildid::read_build_id;
use super::buildid::read_elf_build_id_from_mmap;
use super::buildid::BuildId;
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
            #[cfg(feature = "apk")]
            apk_cache: FileCache::default(),
            entry_cache: InsertMap::new(),
            build_id_cache: FileCache::default(),
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
    /// Cache for APKs as well as build IDs of ELF files inside them.
    #[cfg(feature = "apk")]
    apk_cache: FileCache<(
        zip::Archive,
        InsertMap<Range<u64>, Option<BuildId<'static>>>,
    )>,
    /// If `cache_vmas` is `true`, the cached parsed
    /// [`MapsEntry`][maps::MapsEntry] objects.
    entry_cache: InsertMap<Pid, Box<[maps::MapsEntry]>>,
    /// A cache of build IDs.
    build_id_cache: FileCache<Option<BuildId<'static>>>,
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

    fn normalize_user_addrs_impl<'slf, A, E, M>(
        &'slf self,
        addrs: A,
        entries: E,
        opts: &NormalizeOpts,
    ) -> Result<UserOutput<'slf>>
    where
        A: ExactSizeIterator<Item = Addr> + Clone,
        E: FnMut(Addr) -> Option<Result<M>>,
        M: AsRef<maps::MapsEntry>,
    {
        let addrs_cnt = addrs.len();
        let mut handler = user::NormalizationHandler::new(self, opts, addrs_cnt);
        let () = normalize_sorted_user_addrs_with_entries(addrs, entries, &mut handler)?;
        debug_assert_eq!(handler.normalized.outputs.len(), addrs_cnt);
        Ok(handler.normalized)
    }

    fn normalize_user_addrs_iter<A>(
        &self,
        addrs: A,
        pid: Pid,
        opts: &NormalizeOpts,
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
                self.normalize_user_addrs_impl(addrs, entries, opts)
            } else {
                let entries = self.entry_cache.get_or_try_insert(pid, || {
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
                self.normalize_user_addrs_impl(addrs, entries, opts)
            }
        } else {
            if !self.cache_vmas {
                let mut entry_iter = maps::parse_filtered(pid)?;
                let entries = |_addr| entry_iter.next();
                self.normalize_user_addrs_impl(addrs, entries, opts)
            } else {
                let parsed = self.entry_cache.get_or_try_insert(pid, || {
                    // If we use the cached maps entries but don't have anything
                    // cached yet, then just parse the file eagerly and take it from
                    // there.
                    let parsed = maps::parse_filtered(pid)?.collect::<Result<Box<_>>>()?;
                    Ok(parsed)
                })?;

                let mut entry_iter = parsed.iter().map(Ok);
                let entries = |_addr| entry_iter.next();
                self.normalize_user_addrs_impl(addrs, entries, opts)
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
        if opts.sorted_addrs {
            self.normalize_user_addrs_iter(addrs.iter().copied(), pid, opts)
        } else {
            util::with_ordered_elems(
                addrs,
                |normalized: &mut UserOutput| normalized.outputs.as_mut_slice(),
                |sorted_addrs| self.normalize_user_addrs_iter(sorted_addrs, pid, opts),
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

    /// Read the build ID of a file, honoring various settings.
    #[cfg_attr(feature = "tracing", crate::log::instrument(err, skip_all, fields(path = ?path)))]
    pub(crate) fn read_build_id(&self, path: &Path) -> Result<Option<BuildId<'static>>> {
        let build_id = if self.build_ids {
            if self.cache_build_ids {
                let (file, cell) = self.build_id_cache.entry(path)?;
                cell.get_or_try_init(|| {
                    let parser = ElfParser::from_file(file, path.to_path_buf().into_os_string())?;
                    let build_id =
                        read_build_id(&parser)?.map(|build_id| Cow::Owned(build_id.to_vec()));
                    Result::<_, Error>::Ok(build_id)
                })?
                .clone()
            } else {
                let parser = ElfParser::open(path)?;
                read_build_id(&parser)?.map(|build_id| Cow::Owned(build_id.to_vec()))
            }
        } else {
            // Build ID caching always implies reading of build IDs to
            // begin with.
            debug_assert!(!self.cache_build_ids);
            None
        };
        Ok(build_id)
    }

    /// Translate a file offset inside an APK into a file offset inside
    /// an ELF member inside of it.
    #[cfg(feature = "apk")]
    pub(crate) fn translate_apk_to_elf(
        &self,
        apk_file_off: u64,
        apk_path: &Path,
    ) -> Result<Option<(u64, PathBuf, Option<BuildId<'static>>)>> {
        let (file, cell) = self.apk_cache.entry(apk_path)?;
        let (apk, elf_build_ids) = cell.get_or_try_init(|| {
            let mmap = Mmap::builder()
                .map(file)
                .with_context(|| format!("failed to memory map `{}`", apk_path.display()))?;
            let apk = zip::Archive::with_mmap(mmap)
                .with_context(|| format!("failed to open zip file `{}`", apk_path.display()))?;
            let elf_build_ids = InsertMap::new();
            Result::<_, Error>::Ok((apk, elf_build_ids))
        })?;

        for apk_entry in apk.entries() {
            let apk_entry = apk_entry
                .with_context(|| format!("failed to iterate `{}` members", apk_path.display()))?;
            let bounds = apk_entry.data_offset..apk_entry.data_offset + apk_entry.data.len() as u64;
            if bounds.contains(&apk_file_off) {
                let elf_build_id = if self.build_ids {
                    let mmap = apk
                        .mmap()
                        .constrain(bounds.clone())
                        .ok_or_invalid_input(|| {
                            format!(
                                "invalid APK entry data bounds ({bounds:?}) in {}",
                                apk_path.display()
                            )
                        })?;

                    if self.cache_build_ids {
                        elf_build_ids
                            .get_or_try_insert(bounds.clone(), || {
                                read_elf_build_id_from_mmap(&mmap)
                            })?
                            .clone()
                    } else {
                        read_elf_build_id_from_mmap(&mmap)?
                    }
                } else {
                    None
                };

                let elf_off = apk_file_off - apk_entry.data_offset;
                let elf_path = create_apk_elf_path(apk_path, apk_entry.path);
                return Ok(Some((elf_off, elf_path, elf_build_id)))
            }
        }
        Ok(None)
    }
}

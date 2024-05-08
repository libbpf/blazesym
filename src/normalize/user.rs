use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::path::PathBuf;

use crate::maps::EntryPath;
use crate::maps::MapsEntry;
use crate::maps::PathName;
use crate::Addr;
use crate::BuildId;
use crate::ErrorExt as _;
use crate::Pid;
use crate::Result;

use super::ioctl::procmap_query;
use super::meta::Apk;
use super::meta::Elf;
use super::meta::Unknown;
use super::meta::UserMeta;
use super::normalizer::Output;
use super::Reason;


/// Make a [`UserMeta::Elf`] variant.
fn make_elf_meta<'src>(
    entry_path: &EntryPath,
    build_id: Option<BuildId<'static>>,
) -> Result<UserMeta<'src>> {
    let elf = Elf {
        path: entry_path.symbolic_path.to_path_buf(),
        build_id,
        _non_exhaustive: (),
    };
    let meta = UserMeta::Elf(elf);
    Ok(meta)
}


/// Make a [`UserMeta::Apk`] variant.
fn make_apk_meta(entry_path: &EntryPath) -> Result<UserMeta<'static>> {
    let apk = Apk {
        path: entry_path.symbolic_path.to_path_buf(),
        _non_exhaustive: (),
    };
    let meta = UserMeta::Apk(apk);
    Ok(meta)
}


/// A type representing the output of user addresses normalization.
pub type UserOutput<'src> = Output<UserMeta<'src>>;

impl<'src> UserOutput<'src> {
    /// Add an unknown (non-normalizable) address to this object.
    ///
    /// This function accepts `unknown_idx` which, if not `None`, should
    /// contain the index into [`Self::meta`] at which an [`Unknown`]
    /// without any build ID resides.
    ///
    /// It returns the index of the inserted [`Unknown`] variant. The
    /// return type is an `Option` only for convenience of callers.
    /// Returned is always a `Some`.
    fn add_unknown_addr(
        &mut self,
        addr: Addr,
        reason: Reason,
        unknown_cache: &mut HashMap<Reason, usize>,
    ) {
        let unknown_idx = match unknown_cache.entry(reason) {
            Entry::Occupied(occupied) => {
                let unknown_idx = *occupied.get();
                debug_assert_eq!(self.meta[unknown_idx], Unknown::new(reason).into());
                unknown_idx
            }
            Entry::Vacant(vacancy) => {
                let unknown_idx = self.meta.len();
                let unknown = Unknown::new(reason);
                let () = self.meta.push(UserMeta::Unknown(unknown));
                let idx = vacancy.insert(unknown_idx);
                *idx
            }
        };

        let () = self.outputs.push((addr, unknown_idx));
    }

    /// Add a (normalized) file offset to this object.
    fn add_normalized_offset<F>(
        &mut self,
        file_offset: Addr,
        key: &Path,
        meta_lookup: &mut HashMap<PathBuf, usize>,
        create_meta: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<UserMeta<'src>>,
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

        let () = self.outputs.push((file_offset, meta_idx));
        Ok(())
    }
}


pub(crate) trait Handler<D = ()> {
    /// Handle an unknown address.
    fn handle_unknown_addr(&mut self, addr: Addr, data: D) -> Result<()>;

    /// Handle an address residing in the provided [`MapsEntry`].
    fn handle_entry_addr(&mut self, addr: Addr, entry: &MapsEntry) -> Result<()>;
}


pub(super) struct NormalizationHandler<'src> {
    /// The user output we are building up.
    pub normalized: UserOutput<'src>,
    /// Lookup table from path (as used in each proc maps entry) to index into
    /// `output.meta`.
    meta_lookup: HashMap<PathBuf, usize>,
    /// A mapping from [`Reason`] to the index of the `Unknown` entry with this
    /// very reason in `meta_lookup`, if any.
    unknown_cache: HashMap<Reason, usize>,
}

impl<'src> NormalizationHandler<'src> {
    /// Instantiate a new `NormalizationHandler` object.
    pub fn new(addr_cnt: usize) -> Self {
        Self {
            normalized: UserOutput {
                outputs: Vec::with_capacity(addr_cnt),
                meta: Vec::new(),
            },
            meta_lookup: HashMap::new(),
            unknown_cache: HashMap::new(),
        }
    }
}

impl Handler<Reason> for NormalizationHandler<'_> {
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"))))]
    fn handle_unknown_addr(&mut self, addr: Addr, reason: Reason) -> Result<()> {
        let () = self
            .normalized
            .add_unknown_addr(addr, reason, &mut self.unknown_cache);
        Ok(())
    }

    fn handle_entry_addr(&mut self, addr: Addr, entry: &MapsEntry) -> Result<()> {
        match &entry.path_name {
            Some(PathName::Path(entry_path)) => {
                let file_off = addr - entry.range.start + entry.offset;
                let ext = entry_path
                    .symbolic_path
                    .extension()
                    .unwrap_or_else(|| OsStr::new(""));
                match ext.to_str() {
                    Some("apk") | Some("zip") => self.normalized.add_normalized_offset(
                        file_off,
                        &entry_path.symbolic_path,
                        &mut self.meta_lookup,
                        || make_apk_meta(entry_path),
                    ),
                    _ => self.normalized.add_normalized_offset(
                        file_off,
                        &entry_path.symbolic_path,
                        &mut self.meta_lookup,
                        || make_elf_meta(entry_path, entry.build_id.clone()),
                    ),
                }
            }
            Some(PathName::Component(..)) => self.handle_unknown_addr(addr, Reason::Unsupported),
            // We could still normalize the address and report it, but without a
            // path nobody could really do anything with it.
            None => self.handle_unknown_addr(addr, Reason::MissingComponent),
        }
    }
}


pub(crate) fn normalize_sorted_user_addrs_with_entries<A, R>(
    addrs: A,
    pid: Pid,
    build_ids: bool,
    handler: &mut dyn Handler<R>,
) -> Result<()>
where
    A: Iterator<Item = Addr> + Clone,
    R: From<Reason>,
{
    let path = format!("/proc/{pid}/maps");
    let file =
        File::open(&path).with_context(|| format!("failed to open proc maps file {path}"))?;
    let fd = file.as_fd();
    let first_addr = addrs.clone().next().unwrap();
    let mut entry = procmap_query(fd, pid, first_addr, build_ids)
        .context("procmap_query failed")?
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "did not find any relevant VMAs"))?;

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

        while addr >= entry.as_ref().range.end {
            entry = if let Some(entry) =
                procmap_query(fd, pid, addr, build_ids).context("procmap_query failed")?
            {
                entry
            } else {
                // If there are no proc maps entries left to check, we
                // cannot normalize. We have to assume that addresses
                // were valid and the ELF object was just unmapped,
                // similar to above.
                let () = handler.handle_unknown_addr(addr, R::from(Reason::Unmapped))?;
                continue 'main
            };
        }

        // proc maps entries are always sorted by start address. If the
        // current address lies before the start address at this point,
        // that means that we cannot find a suitable entry. This could
        // happen, for example, if an ELF object was unmapped between
        // address capture and normalization.
        if addr < entry.as_ref().range.start {
            let () = handler.handle_unknown_addr(addr, R::from(Reason::Unmapped))?;
            continue 'main
        }

        let () = handler.handle_entry_addr(addr, entry.as_ref())?;
    }

    Ok(())
}

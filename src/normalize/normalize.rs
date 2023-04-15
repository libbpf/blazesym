use std::collections::HashMap;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::path::PathBuf;

use crate::elf;
use crate::elf::ElfParser;
use crate::maps;
use crate::maps::MapsEntry;
use crate::maps::Pid;
use crate::Addr;

use super::meta::Binary;
use super::meta::Unknown;
use super::meta::UserAddrMeta;


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


/// Normalize a virtual address belonging to an ELF file represented by the
/// provided [`MapsEntry`].
fn normalize_elf_addr(virt_addr: Addr, entry: &MapsEntry) -> Result<Addr> {
    let file_off = virt_addr - entry.range.start + entry.offset as usize;
    let parser = ElfParser::open(&entry.path)?;
    let phdrs = parser.program_headers()?;
    let addr = phdrs
        .iter()
        .find_map(|phdr| {
            if phdr.p_type == elf::types::PT_LOAD {
                if (phdr.p_offset..phdr.p_offset + phdr.p_memsz).contains(&(file_off as u64)) {
                    return Some(file_off - phdr.p_offset as usize + phdr.p_vaddr as usize)
                }
            }
            None
        })
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "failed to find ELF segment in {} that contains file offset 0x{:x}",
                    entry.path.display(),
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
pub fn normalize_user_addrs(addrs: &[Addr], pid: u32) -> Result<NormalizedUserAddrs> {
    let pid = Pid::from(pid);

    let mut entries = maps::parse(pid)?.filter_map(|result| {
        if let Ok(entry) = result {
            maps::is_symbolization_relevant(&entry).then(|| Ok(entry))
        } else {
            Some(result)
        }
    });
    let mut entry = entries.next().ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            format!("proc maps for {pid} does not contain relevant entries"),
        )
    })??;

    // Lookup table from path (as used in each proc maps entry) to index into
    // `normalized.meta`.
    let mut meta_lookup = HashMap::<PathBuf, usize>::new();
    let mut normalized = NormalizedUserAddrs {
        addrs: Vec::with_capacity(addrs.len()),
        meta: Vec::new(),
    };
    // The index of the Unknown entry without any build ID information,
    // used for all unknown addresses.
    let mut unknown_idx = None;

    let mut prev_addr = addrs.first().copied().unwrap_or_default();
    // We effectively do a single pass over `addrs`, advancing to the next
    // proc maps entry whenever the current address is not (or no longer)
    // contained in the current entry's range.
    'main: for addr in addrs.iter().copied() {
        if addr < prev_addr {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "addresses to normalize are not sorted",
            ))
        }
        prev_addr = addr;

        // proc maps entries are always sorted by start address. If the
        // current address lies before the start address at this point,
        // that means that we cannot find a suitable entry. This could
        // happen, for example, if an ELF object was unmapped between
        // address capture and normalization.
        if addr < entry.range.start {
            unknown_idx = normalized.add_unknown_addr(addr, unknown_idx);
            continue 'main
        }

        while addr >= entry.range.end {
            entry = if let Some(entry) = entries.next() {
                entry?
            } else {
                // If there are no proc maps entries left to check, we
                // cannot normalize. We have to assume that addresses
                // were valid and the ELF object was just unmapped,
                // similar to above.
                unknown_idx = normalized.add_unknown_addr(addr, unknown_idx);
                continue 'main
            };
        }

        let meta_idx = if let Some(meta_idx) = meta_lookup.get(&entry.path) {
            *meta_idx
        } else {
            let binary = Binary {
                path: entry.path.to_path_buf(),
                // TODO: Need to find actual build ID.
                build_id: None,
                _non_exhaustive: (),
            };

            let meta_idx = normalized.meta.len();
            let () = normalized.meta.push(UserAddrMeta::Binary(binary));
            let _ref = meta_lookup.insert(entry.path.to_path_buf(), meta_idx);
            meta_idx
        };

        let normalized_addr = normalize_elf_addr(addr, &entry)?;
        let () = normalized.addrs.push((normalized_addr, meta_idx));
    }

    Ok(normalized)
}

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

use crate::maps;
use crate::maps::MapsEntry;
use crate::maps::PathName;
use crate::symbolize::symbolize_with_resolver;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Resolver;
use crate::symbolize::Symbolized;
use crate::vdso::VDSO_MAPS_COMPONENT;
use crate::Addr;
use crate::BuildId;
use crate::Error;
use crate::Pid;
use crate::Result;

#[cfg(feature = "apk")]
use super::meta::Apk;
use super::meta::Elf;
use super::meta::Unknown;
use super::meta::UserMeta;
use super::normalizer::Output;
use super::NormalizeOpts;
use super::Normalizer;
use super::Reason;


/// Make a [`UserMeta::Elf`] variant.
fn make_elf_meta<'src>(path: &Path, build_id: Option<BuildId<'src>>) -> UserMeta<'src> {
    let elf = Elf {
        path: path.to_path_buf(),
        build_id,
        _non_exhaustive: (),
    };
    let meta = UserMeta::Elf(elf);
    meta
}


/// Make a [`UserMeta::Apk`] variant.
#[cfg(feature = "apk")]
fn make_apk_meta(path: &Path) -> UserMeta<'static> {
    let apk = Apk {
        path: path.to_path_buf(),
        _non_exhaustive: (),
    };
    let meta = UserMeta::Apk(apk);
    meta
}


/// A type representing the output of user addresses normalization.
pub type UserOutput<'src> = Output<UserMeta<'src>>;

impl<'src> UserOutput<'src> {
    /// Add an unknown (non-normalizable) address to this object.
    ///
    /// If an [`Unknown`] entry with the provided `reason` exists, add
    /// an output entry pointing to it. Otherwise add one that points to
    /// a newly created entry containing this very reason.
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
        F: FnOnce() -> UserMeta<'src>,
    {
        let meta_idx = if let Some(meta_idx) = meta_lookup.get(key) {
            *meta_idx
        } else {
            let meta = create_meta();
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
    fn handle_unknown_addr(&mut self, addr: Addr, data: D);

    /// Handle an address residing in the provided [`MapsEntry`].
    fn handle_entry_addr(&mut self, addr: Addr, entry: &MapsEntry) -> Result<()>;
}


pub(super) struct NormalizationHandler<'call, 'src> {
    /// The user output we are building up.
    pub normalized: UserOutput<'src>,
    /// The `Normalizer` instance we belong to.
    normalizer: &'call Normalizer,
    /// The options used as part of the normalization request.
    normalize_opts: &'call NormalizeOpts,
    /// The PID of the process in which we normalize.
    pid: Pid,
    /// Lookup table from path (as used in each proc maps entry) to index into
    /// `output.meta`.
    meta_lookup: HashMap<PathBuf, usize>,
    /// A mapping from [`Reason`] to the index of the `Unknown` entry with this
    /// very reason in `meta_lookup`, if any.
    unknown_cache: HashMap<Reason, usize>,
}

impl<'call> NormalizationHandler<'call, '_> {
    /// Instantiate a new `NormalizationHandler` object.
    pub(crate) fn new(
        normalizer: &'call Normalizer,
        opts: &'call NormalizeOpts,
        pid: Pid,
        addr_cnt: usize,
    ) -> Self {
        Self {
            normalized: UserOutput {
                outputs: Vec::with_capacity(addr_cnt),
                meta: Vec::new(),
            },
            normalize_opts: opts,
            normalizer,
            pid,
            meta_lookup: HashMap::new(),
            unknown_cache: HashMap::new(),
        }
    }

    fn handle_vdso_addr(
        &mut self,
        addr: Addr,
        file_off: u64,
        vdso_range: &Range<Addr>,
    ) -> Result<()> {
        let parser = self.normalizer.vdso_parser(self.pid, vdso_range)?;
        if let Some(addr) = parser.file_offset_to_virt_offset(file_off)? {
            // The vDSO is an ELF file with C style names and no source
            // code information. So there is no need for demangling or
            // code info lookup.
            let demangle = false;
            let opts = FindSymOpts::Basic;
            let result = symbolize_with_resolver(addr, &Resolver::Cached(parser), &opts, demangle)?;
            if let Symbolized::Sym(sym) = result {
                let meta_idx = self.normalized.meta.len();
                // We circumvent the meta-data cache here, because we
                // really don't want to cache each and every
                // symbolized symbol.
                let () = self.normalized.meta.push(UserMeta::Sym(sym.into_owned()));
                let () = self.normalized.outputs.push((file_off, meta_idx));
                return Ok(())
            }
        }

        let () = self.handle_unknown_addr(addr, Reason::Unmapped);
        Ok(())
    }
}

impl Handler<Reason> for NormalizationHandler<'_, '_> {
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"))))]
    fn handle_unknown_addr(&mut self, addr: Addr, reason: Reason) {
        let () = self
            .normalized
            .add_unknown_addr(addr, reason, &mut self.unknown_cache);
    }

    fn handle_entry_addr(&mut self, addr: Addr, entry: &MapsEntry) -> Result<()> {
        let file_off = addr - entry.range.start + entry.offset;

        match &entry.path_name {
            Some(PathName::Path(entry_path)) => {
                let path = if self.normalize_opts.map_files {
                    &entry_path.maps_file
                } else {
                    &entry_path.symbolic_path
                };
                let ext = entry_path
                    .symbolic_path
                    .extension()
                    .unwrap_or_else(|| OsStr::new(""));
                match ext.to_str() {
                    #[cfg(feature = "apk")]
                    Some("apk") | Some("zip") => {
                        if self.normalize_opts.apk_to_elf {
                            if let Some((elf_file_off, elf_path, elf_build_id)) =
                                self.normalizer.translate_apk_to_elf(file_off, path)?
                            {
                                self.normalized.add_normalized_offset(
                                    elf_file_off,
                                    &elf_path,
                                    &mut self.meta_lookup,
                                    || {
                                        // We should never have build ID
                                        // on the entry, because that
                                        // can only happen with the
                                        // PROCMAP_QUERY ioctl, and it
                                        // will not report build IDs for
                                        // APK contents.
                                        debug_assert_eq!(entry.build_id, None);
                                        make_elf_meta(&elf_path, elf_build_id)
                                    },
                                )
                            } else {
                                // TODO: Consider using a different reason
                                //       here.
                                let () = self.handle_unknown_addr(addr, Reason::Unmapped);
                                Ok(())
                            }
                        } else {
                            self.normalized.add_normalized_offset(
                                file_off,
                                path,
                                &mut self.meta_lookup,
                                || make_apk_meta(path),
                            )
                        }
                    }
                    _ => self.normalized.add_normalized_offset(
                        file_off,
                        path,
                        &mut self.meta_lookup,
                        || {
                            // Attempt reading the build ID, but only if
                            // one is not already present. A build ID
                            // should only ever be present at this point
                            // if the user opted for PROCMAP_QUERY ioctl
                            // usage. Note that "reading" here could be a
                            // cheap cache look up if build ID caching
                            // is enabled.
                            let build_id = entry.build_id.clone().or_else(|| {
                                // We don't fail normalization due to
                                // build ID read failure.
                                self.normalizer.read_build_id(path).ok().flatten()
                            });
                            make_elf_meta(path, build_id)
                        },
                    ),
                }
            }
            Some(PathName::Component(component)) => {
                match component.as_str() {
                    component if component == VDSO_MAPS_COMPONENT => {
                        let () = self.handle_vdso_addr(addr, file_off, &entry.range)?;
                    }
                    _ => {
                        let () = self.handle_unknown_addr(addr, Reason::Unsupported);
                    }
                }
                Ok(())
            }
            // We could still normalize the address and report it, but without a
            // path nobody could really do anything with it.
            None => {
                let () = self.handle_unknown_addr(addr, Reason::MissingComponent);
                Ok(())
            }
        }
    }
}


pub(crate) fn normalize_sorted_user_addrs_with_entries<A, E, M, R>(
    addrs: A,
    mut entries: E,
    handler: &mut dyn Handler<R>,
) -> Result<()>
where
    A: Iterator<Item = Addr> + Clone,
    E: FnMut(Addr) -> Option<Result<M>>,
    M: AsRef<maps::MapsEntry>,
    R: From<Reason>,
{
    let mut prev_addr = addrs.clone().next().unwrap_or_default();
    let mut entry = entries(prev_addr).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "proc maps does not contain relevant entries",
        )
    })??;

    // We effectively do a single pass over `addrs`, advancing to the next
    // VMA entry whenever the current address is not (or no longer)
    // contained in the current entry's range.
    'main: for addr in addrs {
        if addr < prev_addr {
            return Err(Error::with_invalid_input(
                "addresses to normalize are not sorted",
            ))
        }
        prev_addr = addr;

        while addr >= entry.as_ref().range.end {
            entry = if let Some(entry) = entries(addr) {
                entry?
            } else {
                // If there are no proc maps entries left to check, we
                // cannot normalize. We have to assume that addresses
                // were valid and the ELF object was just unmapped,
                // similar to above.
                let () = handler.handle_unknown_addr(addr, R::from(Reason::Unmapped));
                continue 'main
            };
        }

        // proc maps entries are always sorted by start address. If the
        // current address lies before the start address at this point,
        // that means that we cannot find a suitable entry. This could
        // happen, for example, if an ELF object was unmapped between
        // address capture and normalization.
        if addr < entry.as_ref().range.start {
            let () = handler.handle_unknown_addr(addr, R::from(Reason::Unmapped));
            continue 'main
        }

        let () = handler.handle_entry_addr(addr, entry.as_ref())?;
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::maps::Perm;
    use crate::Pid;


    /// Check that we correctly handle various address normalization errors.
    #[test]
    fn user_address_normalization_static_maps() {
        fn test(unknown_addr: Addr, reason: Reason) {
            let maps = r#"55d3195b7000-55d3195b9000 r--p 00000000 00:12 2015701                    /bin/cat
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
7fd5ba1fe000-7fd5ba200000 -w-p 001c7000 00:12 2088876                    /lib64/libc.so.6
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
            let addrs = [unknown_addr];

            let mut entry_iter = maps::parse_file(maps.as_bytes(), pid)
                .filter(|result| result.as_ref().map(maps::filter_relevant).unwrap_or(true));
            let entries = |_addr| entry_iter.next();

            let normalizer = Normalizer::new();
            let opts = NormalizeOpts::default();
            let mut handler = NormalizationHandler::new(&normalizer, &opts, pid, addrs.len());
            let () = normalize_sorted_user_addrs_with_entries(
                addrs.as_slice().iter().copied(),
                entries,
                &mut handler,
            )
            .unwrap();

            let normalized = handler.normalized;
            assert_eq!(normalized.outputs.len(), 1);
            assert_eq!(normalized.meta.len(), 1);
            assert_eq!(normalized.meta[0], Unknown::new(reason).into());
        }

        test(0x0, Reason::Unmapped);
        test(0x1, Reason::Unmapped);
        test(0x1000, Reason::Unmapped);
        test(0xa0000, Reason::Unmapped);
        test(0x7fd5ba1fe000, Reason::Unmapped);
        test(0x7fd5ba200000, Reason::MissingComponent);
        test(0x7fffffff0000, Reason::Unmapped);
        test(0x7fffffff1000, Reason::Unmapped);
        test(0x7fffffff1001, Reason::Unmapped);
        test(0x7fffffffffff, Reason::Unmapped);
    }

    /// Check that we do not normalize addresses belonging to a
    /// "component" (as opposed to a file).
    #[test]
    fn normalize_various_entries() {
        let addrs = [0x10000, 0x30000];

        let mut entry_iter = [
            Ok(MapsEntry {
                range: 0x10000..0x20000,
                perm: Perm::default(),
                offset: 0,
                path_name: Some(PathName::Component(
                    "doesntreallymatternowdoesit".to_string(),
                )),
                build_id: None,
            }),
            Ok(MapsEntry {
                range: 0x30000..0x40000,
                perm: Perm::default(),
                offset: 0,
                path_name: None,
                build_id: None,
            }),
        ]
        .into_iter();
        let entries = |_addr| entry_iter.next();

        let normalizer = Normalizer::new();
        let opts = NormalizeOpts::default();
        let mut handler = NormalizationHandler::new(&normalizer, &opts, Pid::Slf, addrs.len());
        let () = normalize_sorted_user_addrs_with_entries(
            addrs.as_slice().iter().copied(),
            entries,
            &mut handler,
        )
        .unwrap();

        let normalized = handler.normalized;
        assert_eq!(normalized.outputs.len(), 2);
        assert_eq!(normalized.meta.len(), 2);
        assert_eq!(normalized.meta[0], Unknown::new(Reason::Unsupported).into());
        assert_eq!(
            normalized.meta[1],
            Unknown::new(Reason::MissingComponent).into()
        );
    }
}

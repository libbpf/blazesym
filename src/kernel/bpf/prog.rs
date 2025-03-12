use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::iter;
use std::mem::size_of;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::rc::Rc;
use std::str::FromStr;

use crate::inspect::SymInfo;
use crate::log;
use crate::once::OnceCell;
use crate::symbolize::CodeInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;
use crate::SymType;

use super::sys;
use super::Btf;


/// BPF kernel programs show up with this prefix followed by a tag and
/// some other meta-data.
const BPF_PROG_PREFIX: &str = "bpf_prog_";


#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct BpfTag([u8; 8]);

impl Display for BpfTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for b in self.0 {
            let () = write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 8]> for BpfTag {
    fn from(other: [u8; 8]) -> Self {
        Self(other)
    }
}

impl FromStr for BpfTag {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 2 * size_of::<BpfTag>() {
            return Err(())
        }

        let mut tag = [0; size_of::<BpfTag>()];
        (0..s.len())
            .step_by(2)
            .enumerate()
            .try_for_each(|(i, idx)| {
                tag[i] = u8::from_str_radix(&s[idx..idx + 2], 16).map_err(|_| ())?;
                Ok(())
            })?;

        Ok(Self(tag))
    }
}


/// A cache for BPF program related information.
///
/// The cache allows for convenient look up of BPF program information
/// based on BPF tag. It is necessary because the kernel does not
/// provide the means for mapping from tag to program information, but
/// requires a linear time scan over all active BPF programs.
///
/// The cache does the minimal amount of work to establish the mapping
/// of BPF program information to BPF tag.
#[derive(Debug, Default)]
pub struct BpfInfoCache {
    /// Our mapping from BPF tag to program information.
    ///
    /// Program information is reference counted, because it can be
    /// shared with sub-programs.
    cache: RefCell<HashMap<BpfTag, Rc<sys::bpf_prog_info>>>,
}

impl BpfInfoCache {
    /// Look up BPF program information from the cache.
    #[cfg_attr(feature = "tracing", crate::log::instrument(level = tracing::Level::TRACE, skip_all, fields(tag, result), err(level = tracing::Level::INFO)))]
    fn lookup(&self, tag: BpfTag) -> Result<Option<sys::bpf_prog_info>> {
        let mut cache = self.cache.borrow_mut();
        if let Some(info) = cache.get(&tag) {
            return Ok(Some(**info))
        }

        // If we didn't find the tag inside the cache we have to assume
        // that our cache is outdated. Given how BPF program information
        // retrieval works, we have to iterate over all programs, so
        // clear the cache to remove potentially stale entries.
        let () = cache.clear();

        let mut found = None;
        let mut next_prog_id = 0;

        loop {
            let prog_id = match sys::bpf_prog_get_next_id(next_prog_id) {
                Ok(prog_id) => prog_id,
                Err(err) if err.kind() == io::ErrorKind::NotFound => break,
                Err(err) => return Err(err).context("failed to iterate over BPF programs"),
            };
            let fd = sys::bpf_prog_get_fd_from_id(prog_id).with_context(|| {
                format!("failed to retrieve BPF program file descriptor for program {prog_id}")
            })?;

            let mut info = sys::bpf_prog_info::default();
            let () =
                sys::bpf_prog_get_info_from_fd(fd.as_raw_fd(), &mut info).with_context(|| {
                    format!("failed to retrieve BPF program information for program {prog_id}")
                })?;

            // We are going to need to retrieve additional information
            // about all sub-programs (with different tags but captured
            // by the same `bpf_prog_info`).
            let mut prog_tags = Vec::<BpfTag>::with_capacity(info.nr_prog_tags as _);
            // SAFETY: `BpfTag` is `repr(transparent)` and just eight bytes,
            //         meaning it's valid for any bit pattern, so we can
            //         adjust the vector's length to its capacity.
            let () = unsafe { prog_tags.set_len(prog_tags.capacity()) };

            let mut info = sys::bpf_prog_info {
                nr_prog_tags: info.nr_prog_tags,
                prog_tags: prog_tags.as_mut_ptr() as _,
                ..Default::default()
            };
            let () =
                sys::bpf_prog_get_info_from_fd(fd.as_raw_fd(), &mut info).with_context(|| {
                    format!("failed to retrieve BPF program information for program {prog_id}")
                })?;

            let info = Rc::new(info);

            // We need to map all the known sub-programs to the
            // information that we are working with as well.
            for prog_tag in iter::once(BpfTag::from(info.tag)).chain(prog_tags) {
                if found.is_none() && tag == prog_tag {
                    found = Some(*info);
                }
                let _prev = cache.insert(prog_tag, Rc::clone(&info));
            }

            next_prog_id = prog_id;
        }
        Ok(found)
    }
}


#[derive(Debug)]
struct LineInfoRecord {
    path: Rc<Path>,
    line: u32,
    col: u16,
}


/// Query BPF program line information.
fn query_line_info(
    bpf_fd: BorrowedFd<'_>,
    info: &sys::bpf_prog_info,
) -> Result<Option<Box<[(Addr, LineInfoRecord)]>>> {
    let prog_id = info.id;

    assert_eq!(
        info.line_info_rec_size as usize,
        size_of::<sys::bpf_line_info>()
    );
    let mut line_info = Vec::<sys::bpf_line_info>::with_capacity(info.nr_line_info as _);
    // SAFETY: `bpf_line_info` is valid for any bit pattern, so we
    //         can adjust the vector's length to its capacity.
    let () = unsafe { line_info.set_len(line_info.capacity()) };

    assert_eq!(info.jited_line_info_rec_size as usize, size_of::<u64>());
    let mut jited_line_info = Vec::<u64>::with_capacity(info.nr_jited_line_info as _);
    // SAFETY: `u64` is valid for any bit pattern, so we can adjust
    //         the vector's length to its capacity.
    let () = unsafe { jited_line_info.set_len(jited_line_info.capacity()) };

    let mut info = sys::bpf_prog_info {
        nr_line_info: info.nr_line_info,
        line_info_rec_size: info.line_info_rec_size,
        line_info: line_info.as_mut_ptr() as _,
        nr_jited_line_info: info.nr_jited_line_info,
        jited_line_info_rec_size: info.jited_line_info_rec_size,
        jited_line_info: jited_line_info.as_mut_ptr() as _,
        ..Default::default()
    };
    let () = sys::bpf_prog_get_info_from_fd(bpf_fd.as_raw_fd(), &mut info).with_context(|| {
        format!("failed to retrieve BPF program information for program {prog_id}")
    })?;

    let mut file_cache = HashMap::new();

    let btf = if let Some(btf) = Btf::load_from_id(info.btf_id)
        .with_context(|| format!("failed to load BTF information for program {prog_id}"))?
    {
        btf
    } else {
        // We don't have BTF information available. There is nothing we
        // can do. Bail out gracefully.
        return Ok(None)
    };

    let mut line_records = jited_line_info
        .into_iter()
        .enumerate()
        .map(|(i, addr)| {
            let info = line_info.get(i).ok_or_invalid_data(|| {
                format!("failed to get BPF program {prog_id} line record {i} for address {addr:#x}")
            })?;
            let file = btf.name(info.file_name_off).ok_or_invalid_data(|| {
                format!(
                "failed to retrieve BPF program {prog_id} file information for address {addr:#x}"
            )
            })?;

            // Check if we already have the file cached (and do so if
            // not), to not have dozens of duplicate allocations flying
            // around.
            let path = match file_cache.entry(file) {
                Entry::Vacant(vacancy) => {
                    let path = Rc::<Path>::from(Path::new(file));
                    vacancy.insert(path)
                }
                Entry::Occupied(occupancy) => occupancy.into_mut(),
            };

            let record = LineInfoRecord {
                path: Rc::clone(path),
                line: info.line(),
                col: info.column(),
            };
            Ok((addr, record))
        })
        .collect::<Result<Box<[_]>>>()?;

    let () = line_records.sort_by_key(|(addr, _record)| *addr);
    Ok(Some(line_records))
}


/// Information about a BPF program.
#[derive(Debug)]
pub struct BpfProg {
    addr: Addr,
    name: Box<str>,
    tag: BpfTag,
    line_info: OnceCell<Option<Box<[(Addr, LineInfoRecord)]>>>,
}

impl BpfProg {
    /// Parse information about a BPF program from part of a `kallsyms`
    /// line.
    pub fn parse(s: &str, addr: Addr) -> Option<Self> {
        let s = s.strip_prefix(BPF_PROG_PREFIX)?;
        // The name is "optional".
        let (tag, name) = if let Some(idx) = s.find('_') {
            let (tag, name) = s.split_at(idx);
            // Strip leading underscore from name.
            (tag, &name[1..])
        } else {
            (s, "")
        };

        let tag = BpfTag::from_str(tag).ok()?;
        let prog = BpfProg {
            addr,
            name: Box::from(name),
            tag,
            line_info: OnceCell::new(),
        };
        Some(prog)
    }

    fn retrieve_code_info(
        &self,
        addr: Addr,
        info_cache: &BpfInfoCache,
    ) -> Result<Option<CodeInfo<'_>>> {
        let line_info = self.line_info.get_or_try_init(|| {
            let prog_info = info_cache.lookup(self.tag)?.ok_or_not_found(|| {
                format!(
                    "failed to find information for BPF program with tag {}",
                    self.tag
                )
            })?;

            let fd = sys::bpf_prog_get_fd_from_id(prog_info.id).with_context(|| {
                format!(
                    "failed to retrieve BPF program file descriptor for program {}",
                    prog_info.id
                )
            })?;

            let line_info = query_line_info(fd.as_fd(), &prog_info).with_context(|| {
                format!(
                    "failed to query line information for BPF program {}",
                    prog_info.id
                )
            })?;
            Result::<_, Error>::Ok(line_info)
        })?;

        let code_info = if let Some(line_info) = line_info {
            if let Some(idx) =
                find_match_or_lower_bound_by_key(line_info, addr, |(addr, _record)| *addr)
            {
                let (_addr, record) = &line_info[idx];
                let code_info = CodeInfo {
                    dir: None,
                    file: Cow::Borrowed(record.path.as_os_str()),
                    line: Some(record.line),
                    column: Some(record.col),
                    _non_exhaustive: (),
                };
                Some(code_info)
            } else {
                log::debug!(
                    "BPF code information does not contain information for address {addr:#x}"
                );
                None
            }
        } else {
            log::debug!("BPF program for address {addr:#x} does not have code information present");
            None
        };

        Ok(code_info)
    }

    pub fn resolve(
        &self,
        addr: Addr,
        opts: &FindSymOpts,
        info_cache: &BpfInfoCache,
    ) -> Result<ResolvedSym<'_>> {
        let code_info = if opts.code_info() {
            self.retrieve_code_info(addr, info_cache)?
        } else {
            None
        };

        let BpfProg {
            name,
            addr: prog_addr,
            ..
        } = self;
        let sym = ResolvedSym {
            name,
            module: None,
            addr: *prog_addr,
            // TODO: May be able to use `bpf_prog_info::func_info` here.
            //       Unsure.
            size: None,
            lang: SrcLang::Unknown,
            code_info,
            inlined: Box::new([]),
        };
        Ok(sym)
    }

    /// Retrieve the program's start address.
    pub fn addr(&self) -> Addr {
        self.addr
    }

    /// Retrieve the program's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieve the program's tag.
    pub fn tag(&self) -> BpfTag {
        self.tag
    }
}

impl<'prog> TryFrom<&'prog BpfProg> for SymInfo<'prog> {
    type Error = Error;

    fn try_from(other: &'prog BpfProg) -> Result<Self, Self::Error> {
        let BpfProg { addr, name, .. } = other;
        let sym = SymInfo {
            name: Cow::Borrowed(name),
            addr: *addr,
            size: None,
            sym_type: SymType::Function,
            file_offset: None,
            module: None,
        };
        Ok(sym)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use blazesym_dev::prog_mut;
    use blazesym_dev::test_object;

    use test_log::test;
    use test_tag::tag;


    /// Check that we can convert a `BpfProg` into a `SymInfo`.
    #[tag(miri)]
    #[test]
    fn bpf_prog_conversion() {
        let addr = 0x1337;
        let name = "bpf_prog_30304e82b4033ea3_kprobe__cap_capable";
        let bpf_prog = BpfProg::parse(name, addr).unwrap();

        let sym = SymInfo::try_from(&bpf_prog).unwrap();
        assert_eq!(sym.name, "kprobe__cap_capable");
        assert_eq!(sym.addr, 0x1337);
        assert_eq!(sym.sym_type, SymType::Function);
        assert_eq!(sym.file_offset, None);
    }

    /// Test that we can parse a BPF program string as it may appear in
    /// `kallsyms` successfully.
    #[tag(miri)]
    #[test]
    fn bpf_prog_str_parsing() {
        let addr = 0x1337;
        let name = "bpf_prog_30304e82b4033ea3_kprobe__cap_capable";
        let bpf_prog = BpfProg::parse(name, addr).unwrap();
        assert_eq!(bpf_prog.addr, addr);
        assert_eq!(&*bpf_prog.name, "kprobe__cap_capable");
        assert_eq!(
            bpf_prog.tag,
            BpfTag::from([0x30, 0x30, 0x4e, 0x82, 0xb4, 0x03, 0x3e, 0xa3])
        );
        assert_eq!(bpf_prog.tag.to_string(), "30304e82b4033ea3");

        let name = "bpf_prog_30304e82b4033ea3";
        let bpf_prog = BpfProg::parse(name, addr).unwrap();
        assert_eq!(bpf_prog.addr, addr);
        assert_eq!(&*bpf_prog.name, "");
        assert_eq!(bpf_prog.tag.to_string(), "30304e82b4033ea3");

        let name = "bpf_prog_run";
        assert!(BpfProg::parse(name, addr).is_none());

        let name = "bpf_prog_get_curr_or_next";
        assert!(BpfProg::parse(name, addr).is_none());
    }

    /// Check that we can look up BPF program information through a
    /// `BpfInfoCache` instance.
    #[test]
    fn bpf_info_cache_lookup() {
        let mut obj = test_object("getpid.bpf.o");
        let prog = prog_mut(&mut obj, "handle__getpid");
        let _link = prog
            .attach_tracepoint("syscalls", "sys_enter_getpid")
            .expect("failed to attach prog");

        // Retrieve the program's BPF tag out-of-band so that we know
        // what to look up.
        let fd = prog.as_fd();
        let mut info = sys::bpf_prog_info::default();
        let () = sys::bpf_prog_get_info_from_fd(fd.as_raw_fd(), &mut info).unwrap();
        let tag = BpfTag::from(info.tag);

        let cache = BpfInfoCache::default();
        let info = cache.lookup(tag).unwrap().unwrap();

        assert_eq!(BpfTag::from(info.tag), tag);
    }

    /// Check that we can query line information for all loaded
    /// programs.
    ///
    /// This is mostly meant as a catch-all sanity check, as no programs
    /// *may* be loaded.
    #[test]
    fn line_info_querying() {
        let mut obj = test_object("getpid.bpf.o");
        let prog = prog_mut(&mut obj, "handle__getpid");
        let _link = prog
            .attach_tracepoint("syscalls", "sys_enter_getpid")
            .expect("failed to attach prog");

        let mut next_prog_id = 0;
        while let Ok(prog_id) = sys::bpf_prog_get_next_id(next_prog_id) {
            let fd = sys::bpf_prog_get_fd_from_id(prog_id).unwrap();

            let mut info = sys::bpf_prog_info::default();
            let () = sys::bpf_prog_get_info_from_fd(fd.as_raw_fd(), &mut info).unwrap();

            let _line_info = query_line_info(fd.as_fd(), &info).unwrap();
            next_prog_id = prog_id;
        }
    }
}

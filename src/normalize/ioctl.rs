use std::borrow::Cow;
use std::ffi::c_int;
use std::io;
use std::mem::size_of;
use std::mem::size_of_val;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use libc::ioctl;
use libc::ENOENT;
use libc::ENOTTY;

use crate::maps::EntryPath;
use crate::maps::MapsEntry;
use crate::maps::PathName;
use crate::util::bytes_to_path;
use crate::Addr;
use crate::Error;
use crate::Pid;
use crate::Result;

/// From uapi/linux/fs.h

const PROCFS_IOCTL_MAGIC: usize = 0x9f;
const PROCFS_PROCMAP_QUERY: usize = 0xC0609F01; // _IOWR(PROCFS_IOCTL_MAGIC, 1, struct procfs_procmap_query)

type procmap_query_flags = c_int;

const PROCFS_PROCMAP_EXACT_OR_NEXT_VMA: procmap_query_flags = 0x01;

type procmap_vma_flags = c_int;

const PROCFS_PROCMAP_VMA_READABLE: procmap_vma_flags = 0x01;
const PROCFS_PROCMAP_VMA_WRITABLE: procmap_vma_flags = 0x02;
const PROCFS_PROCMAP_VMA_EXECUTABLE: procmap_vma_flags = 0x04;
const PROCFS_PROCMAP_VMA_SHARED: procmap_vma_flags = 0x08;

#[repr(C)]
#[derive(Clone, Default)]
struct procfs_procmap_query {
    size: u64,
    query_flags: u64,   /* in */
    query_addr: u64,    /* in */
    vma_start: u64,     /* out */
    vma_end: u64,       /* out */
    vma_flags: u64,     /* out */
    vma_offset: u64,    /* out */
    inode: u64,         /* out */
    dev_major: u32,     /* out */
    dev_minor: u32,     /* out */
    vma_name_size: u32, /* in/out */
    build_id_size: u32, /* in/out */
    vma_name_addr: u64, /* in */
    build_id_addr: u64, /* in */
}


/// The caller is responsible for checking that the returned `MapsEntry`
/// actually covers the provided address. If it does not, it represents
/// the next known entry.
pub(crate) fn procmap_query(
    fd: BorrowedFd,
    pid: Pid,
    addr: Addr,
    build_id: bool,
) -> Result<Option<MapsEntry>> {
    // TODO: Actually honor `build_id` flag.

    let mut path_buf = MaybeUninit::<[u8; 4096]>::uninit();
    let mut build_id_buf = MaybeUninit::<[u8; 56]>::uninit();
    let mut query = procfs_procmap_query {
        size: size_of::<procfs_procmap_query>() as _,
        query_flags: PROCFS_PROCMAP_EXACT_OR_NEXT_VMA as _,
        query_addr: addr,
        // TODO: Pointer is probably wrong.
        vma_name_addr: path_buf.as_mut_ptr() as _,
        vma_name_size: size_of_val(&path_buf) as _,
        build_id_addr: build_id_buf.as_mut_ptr() as _,
        build_id_size: size_of_val(&build_id_buf) as _,
        ..Default::default()
    };

    // SAFETY: We know what we are doing. Or do we...?
    let rc = unsafe {
        ioctl(
            fd.as_raw_fd(),
            PROCFS_PROCMAP_QUERY as _,
            &mut query as *mut procfs_procmap_query,
        )
    };
    if rc < 0 {
        let err = unsafe { *libc::__errno_location() };
        if err == ENOTTY {
            return Err(Error::with_unsupported(
                "ioctl PROCFS_PROCMAP_QUERY is not supported",
            ))
        }
        if err == ENOENT {
            return Ok(None)
        }
        return Err(Error::from(io::Error::from_raw_os_error(err)))
    }

    let path_buf = unsafe { path_buf.assume_init_ref() };
    let build_id_buf = unsafe { build_id_buf.assume_init_ref() };

    let maps_file = PathBuf::from(format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        query.vma_start, query.vma_end
    ));
    let symbolic_path =
        bytes_to_path(&path_buf[0..query.vma_name_size.saturating_sub(1) as usize]).to_path_buf();
    let build_id = build_id_buf[0..query.build_id_size as usize].to_vec();
    let entry = MapsEntry {
        range: query.vma_start..query.vma_end,
        // TODO: Need to decode `vma_flags` as `procmap_vma_flags`.
        mode: 0xf,
        offset: query.vma_offset,
        path_name: Some(PathName::Path(EntryPath {
            maps_file,
            symbolic_path,
            _non_exhaustive: (),
        })),
        build_id: Some(Cow::Owned(build_id)),
    };
    Ok(Some(entry))
}

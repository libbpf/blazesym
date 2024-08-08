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

// From uapi/linux/fs.h
const PROCMAP_QUERY: usize = 0xC0686611; // _IOWR(PROCFS_IOCTL_MAGIC, 17, struct procmap_query)

#[allow(non_camel_case_types)]
type procmap_query_flags = c_int;

const PROCMAP_QUERY_VMA_READABLE: procmap_query_flags = 0x01;
const PROCMAP_QUERY_VMA_WRITABLE: procmap_query_flags = 0x02;
const PROCMAP_QUERY_VMA_EXECUTABLE: procmap_query_flags = 0x04;
const PROCMAP_QUERY_COVERING_OR_NEXT_VMA: procmap_query_flags = 0x10;


#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Default)]
struct procmap_query {
    /* Query struct size, for backwards/forward compatibility */
    size: u64,
    /* Query flags, a combination of procmap_query_flags values. Defines
     * query filtering and behavior, see procmap_query_flags.
     */
    query_flags: u64, /* in */
    /* Query address. By default, VMA that covers this address will be
     * looked up. PROCMAP_QUERY_* flags above modify this default
     * behavior further.
     */
    query_addr: u64, /* in */
    /* VMA starting (inclusive) and ending (exclusive) address, if VMA is found. */
    vma_start: u64, /* out */
    vma_end: u64,   /* out */
    /* VMA permissions flags. A combination of PROCMAP_QUERY_VMA_* flags. */
    vma_flags: u64, /* out */
    /* VMA backing page size granularity. */
    vma_page_size: u64, /* out */
    /* VMA file offset. If VMA has file backing, this specifies offset
     * within the file that VMA's start address corresponds to. Is set
     * to zero if VMA has no backing file.
     */
    vma_offset: u64, /* out */
    /* Backing file's inode number, or zero, if VMA has no backing file. */
    inode: u64, /* out */
    /* Backing file's device major/minor number, or zero, if VMA has no backing file. */
    dev_major: u32, /* out */
    dev_minor: u32, /* out */
    /* If set to non-zero value, signals the request to return VMA name
     * (i.e., VMA's backing file's absolute path, with " (deleted)" suffix
     * appended, if file was unlinked from FS) for matched VMA. VMA name
     * can also be some special name (e.g., "[heap]", "[stack]") or could
     * be even user-supplied with prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME).
     *
     * Kernel will set this field to zero, if VMA has no associated name.
     * Otherwise kernel will return actual amount of bytes filled in
     * user-supplied buffer (see vma_name_addr field below), including the
     * terminating zero.
     *
     * If VMA name is longer that user-supplied maximum buffer size,
     * -E2BIG error is returned.
     *
     * If this field is set to non-zero value, vma_name_addr should point
     * to valid user space memory buffer of at least vma_name_size bytes.
     * If set to zero, vma_name_addr should be set to zero as well
     */
    vma_name_size: u32, /* in/out */
    /* If set to non-zero value, signals the request to extract and return
     * VMA's backing file's build ID, if the backing file is an ELF file
     * and it contains embedded build ID.
     *
     * Kernel will set this field to zero, if VMA has no backing file,
     * backing file is not an ELF file, or ELF file has no build ID
     * embedded.
     *
     * Build ID is a binary value (not a string). Kernel will set
     * build_id_size field to exact number of bytes used for build ID.
     * If build ID is requested and present, but needs more bytes than
     * user-supplied maximum buffer size (see build_id_addr field below),
     * -E2BIG error will be returned.
     *
     * If this field is set to non-zero value, build_id_addr should point
     * to valid user space memory buffer of at least build_id_size bytes.
     * If set to zero, build_id_addr should be set to zero as well
     */
    build_id_size: u32, /* in/out */
    /* User-supplied address of a buffer of at least vma_name_size bytes
     * for kernel to fill with matched VMA's name (see vma_name_size field
     * description above for details).
     *
     * Should be set to zero if VMA name should not be returned.
     */
    vma_name_addr: u64, /* in */
    /* User-supplied address of a buffer of at least build_id_size bytes
     * for kernel to fill with matched VMA's ELF build ID, if available
     * (see build_id_size field description above for details).
     *
     * Should be set to zero if build ID should not be returned.
     */
    build_id_addr: u64, /* in */
}


fn vma_flags_to_mode(vma_flags: u64) -> u8 {
    let vma_flags = vma_flags as i32;
    let mut mode = 0;

    if vma_flags & PROCMAP_QUERY_VMA_READABLE != 0 {
        mode |= 0b1000;
    }
    if vma_flags & PROCMAP_QUERY_VMA_WRITABLE != 0 {
        mode |= 0b0100;
    }
    if vma_flags & PROCMAP_QUERY_VMA_EXECUTABLE != 0 {
        mode |= 0b0010;
    }
    mode
}


/// The caller is responsible for checking that the returned `MapsEntry`
/// actually covers the provided address. If it does not, it represents
/// the next known entry.
pub(crate) fn query_procmap(
    fd: BorrowedFd,
    pid: Pid,
    addr: Addr,
    build_id: bool,
) -> Result<Option<MapsEntry>> {
    let mut path_buf = MaybeUninit::<[u8; 4096]>::uninit();
    let mut build_id_buf = MaybeUninit::<[u8; 56]>::uninit();
    let mut query = procmap_query {
        size: size_of::<procmap_query>() as _,
        query_flags: (PROCMAP_QUERY_COVERING_OR_NEXT_VMA
            // NB: Keep filter flags in sync with `filter_relevant`
            //     function.
            | PROCMAP_QUERY_VMA_READABLE
            | PROCMAP_QUERY_VMA_EXECUTABLE) as _,
        query_addr: addr,
        vma_name_addr: path_buf.as_mut_ptr() as _,
        vma_name_size: size_of_val(&path_buf) as _,
        build_id_addr: if build_id {
            build_id_buf.as_mut_ptr() as _
        } else {
            0
        },
        build_id_size: if build_id {
            size_of_val(&build_id_buf) as _
        } else {
            0
        },
        ..Default::default()
    };

    // SAFETY: The `procmap_query` pointer is valid because it comes
    //         from a reference.
    let rc = unsafe {
        ioctl(
            fd.as_raw_fd(),
            PROCMAP_QUERY as _,
            &mut query as *mut procmap_query,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(e) if e == ENOTTY => {
                return Err(Error::with_unsupported("PROCMAP_QUERY is not supported"))
            }
            Some(e) if e == ENOENT => return Ok(None),
            _ => (),
        }
        return Err(Error::from(err))
    }

    // SAFETY: The kernel will have set the member to a valid value.
    let path_buf = unsafe { path_buf.assume_init_ref() };

    let maps_file = PathBuf::from(format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        query.vma_start, query.vma_end
    ));
    let symbolic_path =
        bytes_to_path(&path_buf[0..query.vma_name_size.saturating_sub(1) as usize])?.to_path_buf();
    let mut entry = MapsEntry {
        range: query.vma_start..query.vma_end,
        mode: vma_flags_to_mode(query.vma_flags),
        offset: query.vma_offset,
        path_name: Some(PathName::Path(EntryPath {
            maps_file,
            symbolic_path,
            _non_exhaustive: (),
        })),
        build_id: None,
    };

    if build_id {
        // SAFETY: The kernel will have set the member to a valid value
        //         because we asked it to.
        let build_id_buf = unsafe { build_id_buf.assume_init_ref() };
        let build_id = build_id_buf[0..query.build_id_size as usize].to_vec();
        entry.build_id = Some(Cow::Owned(build_id));
    }
    Ok(Some(entry))
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env::current_exe;
    use std::fs::File;
    use std::os::fd::AsFd as _;

    use super::super::buildid::read_elf_build_id;


    /// Check that we can convert VMA flags to our "mode" thingy.
    #[test]
    fn vma_flags_conversion() {
        let flags = 0;
        assert_eq!(vma_flags_to_mode(flags as _), 0b0000);

        let flags = PROCMAP_QUERY_VMA_READABLE;
        assert_eq!(vma_flags_to_mode(flags as _), 0b1000);

        let flags = PROCMAP_QUERY_VMA_READABLE | PROCMAP_QUERY_VMA_WRITABLE;
        assert_eq!(vma_flags_to_mode(flags as _), 0b1100);

        let flags = PROCMAP_QUERY_VMA_EXECUTABLE;
        assert_eq!(vma_flags_to_mode(flags as _), 0b0010);

        let flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA | PROCMAP_QUERY_VMA_EXECUTABLE;
        assert_eq!(vma_flags_to_mode(flags as _), 0b0010);
    }


    /// Check that we can query VMA regions using the PROCMAP_QUERY
    /// ioctl.
    #[test]
    #[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
    fn vma_querying_ioctl() {
        fn test(build_ids: bool) {
            let pid = Pid::Slf;
            let path = format!("/proc/{pid}/maps");
            let file = File::open(path).unwrap();
            let fd = file.as_fd();
            let addr = vma_querying_ioctl as Addr;
            let entry = query_procmap(fd, pid, addr, build_ids).unwrap().unwrap();
            assert!(
                entry.range.contains(&addr),
                "{:#x?} : {addr:#x}",
                entry.range
            );
            // The region should be readable (r---) and executable (--x-), as
            // it's code.
            assert_eq!(entry.mode, 0b1010);
            let exe = current_exe().unwrap();
            assert_eq!(
                entry
                    .path_name
                    .as_ref()
                    .unwrap()
                    .as_path()
                    .unwrap()
                    .symbolic_path,
                exe
            );

            if build_ids {
                let build_id = read_elf_build_id(&exe).unwrap();
                assert_eq!(entry.build_id, build_id);
            } else {
                assert_eq!(entry.build_id, None);
            }
        }

        test(false);
        test(true);
    }
}

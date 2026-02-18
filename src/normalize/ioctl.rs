use std::borrow::Cow;
use std::ffi::c_int;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::mem::size_of_val;
use std::mem::MaybeUninit;

use libc::ENOENT;
use libc::ENOTTY;

use crate::maps::MapsEntry;
use crate::maps::Perm;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::ErrorKind;
use crate::Pid;
use crate::Result;

// From uapi/linux/fs.h
const PROCMAP_QUERY: usize = 0xC0686611; // _IOWR(PROCFS_IOCTL_MAGIC, 17, struct procmap_query)

#[expect(non_camel_case_types)]
type procmap_query_flags = c_int;

const PROCMAP_QUERY_VMA_READABLE: procmap_query_flags = 0x01;
const PROCMAP_QUERY_VMA_WRITABLE: procmap_query_flags = 0x02;
const PROCMAP_QUERY_VMA_EXECUTABLE: procmap_query_flags = 0x04;
#[cfg(test)]
const PROCMAP_QUERY_VMA_SHARED: procmap_query_flags = 0x08;
const PROCMAP_QUERY_COVERING_OR_NEXT_VMA: procmap_query_flags = 0x10;


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


fn vma_flags_to_perm(vma_flags: u64) -> Perm {
    let vma_flags = vma_flags as i32;
    let mut perm = Perm::default();

    if vma_flags & PROCMAP_QUERY_VMA_READABLE != 0 {
        perm |= Perm::R;
    }
    if vma_flags & PROCMAP_QUERY_VMA_WRITABLE != 0 {
        perm |= Perm::W;
    }
    if vma_flags & PROCMAP_QUERY_VMA_EXECUTABLE != 0 {
        perm |= Perm::X;
    }
    perm
}


/// The caller is responsible for checking that the returned `MapsEntry`
/// actually covers the provided address. If it does not, it represents
/// the next known entry.
#[cfg(linux)]
pub(crate) fn query_procmap(
    file: &File,
    pid: Pid,
    addr: Addr,
    build_id: bool,
) -> Result<Option<MapsEntry>> {
    use libc::ioctl;
    use std::os::unix::io::AsFd as _;
    use std::os::unix::io::AsRawFd as _;

    use crate::maps::parse_path_name;

    let mut path_buf = MaybeUninit::<[u8; 4096]>::uninit();
    let mut build_id_buf = MaybeUninit::<[u8; 56]>::uninit();
    let mut query = procmap_query {
        size: size_of::<procmap_query>() as _,
        query_flags: (PROCMAP_QUERY_COVERING_OR_NEXT_VMA
            // NB: Keep filter flags roughly in sync with
            //     `filter_relevant` function. Note that because the
            //     ioctl ANDs the conditions, we can't mirror exactly
            //     what `filter_relevant` does (r OR x). So we just
            //     filter for readable, pretty much all things
            //     executable will be readable anyway.
            | PROCMAP_QUERY_VMA_READABLE) as _,
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
            file.as_fd().as_raw_fd(),
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
    let path = &path_buf[0..query.vma_name_size.saturating_sub(1) as usize];
    let path_name = parse_path_name(path, pid, query.vma_start, query.vma_end)?;

    let mut entry = MapsEntry {
        range: query.vma_start..query.vma_end,
        perm: vma_flags_to_perm(query.vma_flags),
        offset: query.vma_offset,
        path_name,
        build_id: None,
    };

    if build_id && query.build_id_size > 0 {
        // SAFETY: The kernel will have set the member to a valid value
        //         because we asked it to.
        let build_id_buf = unsafe { build_id_buf.assume_init_ref() };
        let build_id = build_id_buf[0..query.build_id_size as usize].to_vec();
        entry.build_id = Some(Cow::Owned(build_id));
    }
    Ok(Some(entry))
}

#[cfg(not(linux))]
pub(crate) fn query_procmap(
    _file: &File,
    _pid: Pid,
    _addr: Addr,
    _build_id: bool,
) -> Result<Option<MapsEntry>> {
    unimplemented!()
}


/// Check whether the `PROCMAP_QUERY` ioctl is supported by the system.
pub fn is_procmap_query_supported() -> Result<bool> {
    let pid = Pid::Slf;
    let path = format!("/proc/{pid}/maps");
    let file = File::open(&path).with_context(|| format!("failed to open `{path}` for reading"))?;
    let addr = 0;
    let build_ids = false;

    let result = query_procmap(&file, pid, addr, build_ids);
    match result {
        Ok(..) => Ok(true),
        Err(err) if err.kind() == ErrorKind::Unsupported => Ok(false),
        Err(err) => Err(err),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env::current_exe;
    use std::fs::File;
    use std::thread::sleep;
    use std::time::Duration;

    use crate::maps;

    use super::super::buildid::read_elf_build_id;


    /// Check that we can convert VMA flags into a [`Perm`].
    #[test]
    fn vma_flags_conversion() {
        let flags = 0;
        assert_eq!(vma_flags_to_perm(flags as _), Perm::default());

        let flags = PROCMAP_QUERY_VMA_READABLE;
        assert_eq!(vma_flags_to_perm(flags as _), Perm::R);

        let flags = PROCMAP_QUERY_VMA_READABLE | PROCMAP_QUERY_VMA_WRITABLE;
        assert_eq!(vma_flags_to_perm(flags as _), Perm::RW);

        let flags = PROCMAP_QUERY_VMA_EXECUTABLE | PROCMAP_QUERY_VMA_SHARED;
        assert_eq!(vma_flags_to_perm(flags as _), Perm::X);

        let flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA | PROCMAP_QUERY_VMA_EXECUTABLE;
        assert_eq!(vma_flags_to_perm(flags as _), Perm::X);
    }

    /// Test that we can check whether the `PROCMAP_QUERY` ioctl is
    /// supported.
    #[test]
    fn procmap_query_supported() {
        let _supported = is_procmap_query_supported().unwrap();
    }

    /// Check that we can query an invalid VMA region using the
    /// `PROCMAP_QUERY` ioctl.
    #[test]
    #[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
    fn invalid_vma_querying_ioctl() {
        let pid = Pid::Slf;
        let path = format!("/proc/{pid}/maps");
        let file = File::open(path).unwrap();
        let addr = 0xfffffffff000;
        let result = query_procmap(&file, pid, addr, false).unwrap();
        assert_eq!(result, None);
    }

    /// Check that we can query a valid VMA region using the
    /// `PROCMAP_QUERY` ioctl.
    #[test]
    #[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
    fn valid_vma_querying_ioctl() {
        fn test(build_ids: bool) {
            let pid = Pid::Slf;
            let path = format!("/proc/{pid}/maps");
            let file = File::open(path).unwrap();
            let addr = valid_vma_querying_ioctl as *const () as Addr;
            let entry = query_procmap(&file, pid, addr, build_ids).unwrap().unwrap();
            assert!(
                entry.range.contains(&addr),
                "{:#x?} : {addr:#x}",
                entry.range
            );
            // The region should be readable (r---) and executable (--x-), as
            // it's code.
            assert_eq!(entry.perm, Perm::RX);
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

    /// Check that we see the same number of VMAs reported when using
    /// `/proc/self/maps` parsing versus the `PROCMAP_QUERY` ioctl.
    #[test]
    #[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
    fn vma_comparison() {
        fn parse_maps(pid: Pid, from_text: &mut Vec<MapsEntry>) {
            let () = from_text.clear();

            let it = maps::parse_filtered(pid).unwrap();
            for result in it {
                let vma = result.unwrap();
                let () = from_text.push(vma);
            }
        }

        fn parse_ioctl(pid: Pid, from_ioctl: &mut Vec<MapsEntry>) {
            let () = from_ioctl.clear();

            let path = format!("/proc/{pid}/maps");
            let file = File::open(path).unwrap();
            let build_ids = false;
            let mut next_addr = 0;
            while let Some(entry) = query_procmap(&file, pid, next_addr, build_ids).unwrap() {
                next_addr = entry.range.end;
                if maps::filter_relevant(&entry) {
                    let () = from_ioctl.push(entry);
                }
            }
        }

        let pid = Pid::Slf;
        let mut from_text = Vec::new();
        let mut from_ioctl = Vec::new();

        // The gathering itself has the potential to affect VMAs (e.g.,
        // if the heap has to grow), meaning that we could see
        // mismatches for good reason. So we give it a few attempts.
        for _ in 0..5 {
            let () = parse_maps(pid, &mut from_text);
            let () = parse_ioctl(pid, &mut from_ioctl);

            if from_text == from_ioctl {
                break
            }

            sleep(Duration::from_millis(500));
        }

        assert_eq!(from_text, from_ioctl, "{from_text:#x?}\n{from_ioctl:#x?}");
    }
}

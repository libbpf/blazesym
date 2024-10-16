#![allow(non_camel_case_types)]

use std::ffi::c_long;
use std::ffi::c_uint;
use std::io;
use std::mem::size_of;
use std::mem::size_of_val;
use std::os::fd::FromRawFd as _;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

use libc::syscall;
use libc::SYS_bpf;

type bpf_cmd = c_uint;

const BPF_PROG_GET_NEXT_ID: bpf_cmd = 11;
const BPF_PROG_GET_FD_BY_ID: bpf_cmd = 13;
const BPF_OBJ_GET_INFO_BY_FD: bpf_cmd = 15;
const BPF_BTF_GET_FD_BY_ID: bpf_cmd = 19;


#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct bpf_line_info {
    pub insn_off: u32,
    pub file_name_off: u32,
    pub line_off: u32,
    pub line_col: u32,
}

impl bpf_line_info {
    pub fn line(&self) -> u32 {
        self.line_col >> 10
    }

    pub fn column(&self) -> u16 {
        (self.line_col & 0x3ff) as _
    }
}


#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct bpf_prog_info {
    pub type_: u32,
    pub id: u32,
    pub tag: [u8; 8usize],
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: u64,
    pub xlated_prog_insns: u64,
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub name: [u8; 16usize],
    pub ifindex: u32,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: [u8; 4usize],
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: u64,
    pub jited_func_lens: u64,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: u64,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub recursion_misses: u64,
    pub verified_insns: u32,
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
    pub __bindgen_padding_0: [u8; 4usize],
}


#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct bpf_btf_info {
    pub btf: u64,
    pub btf_size: u32,
    pub id: u32,
    pub name: u64,
    pub name_len: u32,
    pub kernel_btf: u32,
}


#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct btf_header {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}


/// Defined in `include/uapi/linux/bpf.h`.
#[repr(C)]
#[derive(Copy, Clone)]
union bpf_attr {
    pub __bindgen_anon_6: bpf_attr__bindgen_ty_8,
    pub info: bpf_attr__bindgen_ty_9,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct bpf_attr__bindgen_ty_8 {
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_8__bindgen_ty_1,
    pub next_id: u32,
    pub open_flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
union bpf_attr__bindgen_ty_8__bindgen_ty_1 {
    pub start_id: u32,
    pub prog_id: u32,
    pub map_id: u32,
    pub btf_id: u32,
    pub link_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct bpf_attr__bindgen_ty_9 {
    pub bpf_fd: u32,
    pub info_len: u32,
    pub info: u64,
}


fn sys_bpf(cmd: bpf_cmd, attr: *mut bpf_attr, attr_size: usize) -> io::Result<c_long> {
    let rc = unsafe { syscall(SYS_bpf, cmd, attr, attr_size) };
    if rc < 0 {
        // NB: `syscall` is libc provided and takes care of managing
        //     `errno` for us, which is what `io::Error::last_os_error`
        //     relies on.
        return Err(io::Error::last_os_error())
    }
    Ok(rc)
}

pub fn bpf_prog_get_next_id(start_id: u32) -> io::Result<u32> {
    let mut attr = bpf_attr {
        __bindgen_anon_6: bpf_attr__bindgen_ty_8 {
            __bindgen_anon_1: bpf_attr__bindgen_ty_8__bindgen_ty_1 { start_id },
            next_id: 0,
            open_flags: 0,
        },
    };

    let attr_size = unsafe { size_of_val(&attr.__bindgen_anon_6) };
    let _rc = sys_bpf(BPF_PROG_GET_NEXT_ID, &mut attr, attr_size)?;
    Ok(unsafe { attr.__bindgen_anon_6.next_id })
}

pub fn bpf_prog_get_fd_from_id(prog_id: u32) -> io::Result<OwnedFd> {
    let mut attr = bpf_attr {
        __bindgen_anon_6: bpf_attr__bindgen_ty_8 {
            __bindgen_anon_1: bpf_attr__bindgen_ty_8__bindgen_ty_1 { prog_id },
            next_id: 0,
            open_flags: 0,
        },
    };

    let attr_size = unsafe { size_of_val(&attr.__bindgen_anon_6) };
    let fd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &mut attr, attr_size)?;
    // SAFETY: The system call was checked for success and on success a
    //         valid owned file descriptor is returned.
    let fd = unsafe { OwnedFd::from_raw_fd(fd.try_into().unwrap()) };
    Ok(fd)
}

fn bpf_obj_get_info_from_fd<I>(bpf_fd: RawFd, info: &mut I) -> io::Result<()> {
    let mut attr = bpf_attr {
        info: bpf_attr__bindgen_ty_9 {
            bpf_fd: bpf_fd as _,
            info_len: size_of::<I>() as _,
            // NB: Evidently `info` is not just used as output argument
            //     but also as input.
            info: info as *mut _ as usize as _,
        },
    };

    let attr_size = unsafe { size_of_val(&attr.info) };
    let _rc = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr, attr_size)?;
    // TODO: May need to double check `attr.info.info_len`?
    Ok(())
}

pub fn bpf_prog_get_info_from_fd(bpf_fd: RawFd, info: &mut bpf_prog_info) -> io::Result<()> {
    bpf_obj_get_info_from_fd::<bpf_prog_info>(bpf_fd, info)
}

pub fn bpf_btf_get_fd_from_id(btf_id: u32) -> io::Result<OwnedFd> {
    let mut attr = bpf_attr {
        __bindgen_anon_6: bpf_attr__bindgen_ty_8 {
            __bindgen_anon_1: bpf_attr__bindgen_ty_8__bindgen_ty_1 { btf_id },
            next_id: 0,
            open_flags: 0,
        },
    };

    let attr_size = unsafe { size_of_val(&attr.__bindgen_anon_6) };
    let fd = sys_bpf(BPF_BTF_GET_FD_BY_ID, &mut attr, attr_size)?;
    // SAFETY: The system call was checked for success and on success a
    //         valid owned file descriptor is returned.
    let fd = unsafe { OwnedFd::from_raw_fd(fd.try_into().unwrap()) };
    Ok(fd)
}

pub fn bpf_btf_get_info_from_fd(btf_fd: RawFd, info: &mut bpf_btf_info) -> io::Result<()> {
    bpf_obj_get_info_from_fd(btf_fd, info)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CStr;
    use std::os::fd::AsRawFd as _;

    use crate::test_helper::prog_mut;
    use crate::test_helper::test_object;

    use tempfile::tempfile;


    /// Make sure that we fail `bpf_prog_get_info_by_fd` as expected
    /// when an unsupported file descriptor type is presented.
    #[test]
    fn invalid_prog_info_retrieval() {
        let file = tempfile().unwrap();
        let mut info = bpf_prog_info::default();
        let err = bpf_prog_get_info_from_fd(file.as_raw_fd(), &mut info).unwrap_err();
        // We invoked the function with a regular file, not a BPF
        // program file descriptor.
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Check that we can retrieve a BPF program's ID.
    #[test]
    fn prog_discovery() {
        let mut obj = test_object("getpid.bpf.o");
        let prog = prog_mut(&mut obj, "handle__getpid");
        let _link = prog
            .attach_tracepoint("syscalls", "sys_enter_getpid")
            .expect("failed to attach prog");

        let prog_id = 0;
        // Given that we just loaded a program, we should be able to find
        // at least one.
        let prog_id = bpf_prog_get_next_id(prog_id).unwrap();
        assert_ne!(prog_id, 0);
        let fd = bpf_prog_get_fd_from_id(prog_id).unwrap();
        assert_ne!(fd.as_raw_fd(), 0);
    }

    /// Check that we can iterate over all active BPF programs.
    #[test]
    fn prog_iteration() {
        let mut obj = test_object("getpid.bpf.o");
        let prog = prog_mut(&mut obj, "handle__getpid");
        let _link = prog
            .attach_tracepoint("syscalls", "sys_enter_getpid")
            .expect("failed to attach prog");

        let mut next_prog_id = 0;
        while let Ok(prog_id) = bpf_prog_get_next_id(next_prog_id) {
            let fd = bpf_prog_get_fd_from_id(prog_id).unwrap();
            let mut info = bpf_prog_info::default();
            let () = bpf_prog_get_info_from_fd(fd.as_raw_fd(), &mut info).unwrap();
            println!(
                "found BPF program: {}",
                CStr::from_bytes_until_nul(info.name.as_slice())
                    .unwrap()
                    .to_string_lossy()
            );
            next_prog_id = prog_id;
        }
    }
}

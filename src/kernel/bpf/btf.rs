use std::ffi::CStr;
use std::ffi::OsStr;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;

use crate::Error;
use crate::ErrorExt as _;
use crate::Result;

use super::sys;


/// A type encapsulating kernel provided BPF type information.
///
/// <https://www.kernel.org/doc/html/latest/bpf/btf.html>
#[derive(Debug)]
pub(crate) struct Btf {
    /// The complete BTF data, including the "raw" header bytes.
    data: Vec<u8>,
    /// The extracted BTF header.
    header: sys::btf_header,
}

impl Btf {
    /// Load BTF information with the given ID from the kernel.
    pub fn load_from_id(btf_id: u32) -> Result<Option<Btf>> {
        // A BTF ID of 0 means that there is no BTF information present.
        if btf_id == 0 {
            return Ok(None)
        }

        let btf_fd = sys::bpf_btf_get_fd_from_id(btf_id)
            .with_context(|| format!("failed to retrieve BTF file descriptor for ID {btf_id}"))?;

        // Do a first call to retrieve the BTF size we need.
        let mut btf_info = sys::bpf_btf_info::default();
        let () = sys::bpf_btf_get_info_from_fd(btf_fd.as_raw_fd(), &mut btf_info)
            .with_context(|| format!("failed to retrieve BTF information for ID {btf_id}"))?;

        // Now call again to retrieve the actual data.
        let mut btf_data = Vec::<u8>::with_capacity(btf_info.btf_size as _);
        // SAFETY: `btf_data` is valid for any bit pattern, so we can
        //         adjust the vector's length to its capacity.
        let () = unsafe { btf_data.set_len(btf_data.capacity()) };

        let mut btf_info = sys::bpf_btf_info {
            btf: btf_data.as_mut_ptr() as _,
            btf_size: btf_data.capacity() as _,
            ..Default::default()
        };
        let () = sys::bpf_btf_get_info_from_fd(btf_fd.as_raw_fd(), &mut btf_info)
            .with_context(|| format!("failed to retrieve BTF information for ID {btf_id}"))?;

        let header = unsafe {
            btf_data
                .as_mut_ptr()
                .cast::<sys::btf_header>()
                .read_unaligned()
        };

        if header.magic != 0xeb9f {
            return Err(Error::with_unsupported(format!(
                "encountered unsupported BTF magic number ({:#x})",
                header.magic
            )))
        }

        if header.version != 1 {
            return Err(Error::with_unsupported(format!(
                "encountered unsupported BTF version ({})",
                header.version
            )))
        }

        let slf = Self {
            data: btf_data,
            header,
        };
        Ok(Some(slf))
    }

    /// Retrieve a slice representing the BTF string data.
    fn raw_strs(&self) -> &[u8] {
        let start = self.header.hdr_len as usize + self.header.str_off as usize;
        let end = start + self.header.str_len as usize;
        // SANITY: Sub-slice calculation is based on data provided by the
        //         kernel, which is trusted.
        self.data.get(start..end).unwrap()
    }

    /// Retrieve the "name" at the given offset.
    pub fn name(&self, offset: u32) -> Option<&OsStr> {
        let name = self.raw_strs().get(offset as _..)?;
        // SANITY: The strings are trusted and laid out by the kernel;
        //         each entry has to be valid or it's a bug.
        let name = CStr::from_bytes_until_nul(name).unwrap();
        Some(OsStr::from_bytes(name.to_bytes()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helper::prog_mut;
    use crate::test_helper::test_object;

    use test_tag::tag;


    /// Check that we can query the string at an offset from the BTF.
    #[tag(miri)]
    #[test]
    // Endianess shouldn't *really* matter, because we just instantiate
    // a blog without going through the regular constructor, but we
    // captured everything on a little endian system and it's just wrong
    // to expect it to work on a big endian one, no matter the outcome.
    #[cfg(target_endian = "little")]
    fn btf_name_query() {
        // BTF blob was captured from a live instance of our "getpid"
        // program.
        let btf = Btf {
            data: vec![
                159, 235, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 96, 2, 0, 0, 96, 2, 0, 0, 18, 2, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0,
                0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0,
                0, 0, 0, 0, 0, 4, 0, 0, 4, 32, 0, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 30, 0,
                0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 42, 0, 0, 0, 7, 0, 0, 0, 128, 0, 0, 0, 51, 0, 0, 0,
                7, 0, 0, 0, 192, 0, 0, 0, 62, 0, 0, 0, 0, 0, 0, 14, 9, 0, 0, 0, 1, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 2, 12, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 1, 8, 0, 0, 0, 64, 0, 0, 0, 0,
                0, 0, 0, 1, 0, 0, 13, 2, 0, 0, 0, 95, 0, 0, 0, 11, 0, 0, 0, 99, 0, 0, 0, 1, 0, 0,
                12, 13, 0, 0, 0, 9, 1, 0, 0, 5, 0, 0, 4, 32, 0, 0, 0, 21, 1, 0, 0, 16, 0, 0, 0, 0,
                0, 0, 0, 27, 1, 0, 0, 18, 0, 0, 0, 64, 0, 0, 0, 31, 1, 0, 0, 16, 0, 0, 0, 128, 0,
                0, 0, 46, 1, 0, 0, 20, 0, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 192, 0, 0,
                0, 58, 1, 0, 0, 0, 0, 0, 8, 17, 0, 0, 0, 64, 1, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 28, 0, 0, 0,
                77, 1, 0, 0, 4, 0, 0, 6, 4, 0, 0, 0, 93, 1, 0, 0, 0, 0, 0, 0, 110, 1, 0, 0, 1, 0,
                0, 0, 128, 1, 0, 0, 2, 0, 0, 0, 147, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 5,
                4, 0, 0, 0, 164, 1, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 171, 1, 0, 0, 22, 0, 0, 0, 0, 0,
                0, 0, 176, 1, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 236, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
                8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 23, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0,
                0, 241, 1, 0, 0, 0, 0, 0, 14, 24, 0, 0, 0, 1, 0, 0, 0, 249, 1, 0, 0, 1, 0, 0, 15,
                32, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 255, 1, 0, 0, 1, 0, 0, 15, 4, 0,
                0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 7, 2, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0,
                105, 110, 116, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80,
                69, 95, 95, 0, 116, 121, 112, 101, 0, 109, 97, 120, 95, 101, 110, 116, 114, 105,
                101, 115, 0, 107, 101, 121, 95, 115, 105, 122, 101, 0, 118, 97, 108, 117, 101, 95,
                115, 105, 122, 101, 0, 104, 105, 100, 95, 106, 109, 112, 95, 116, 97, 98, 108, 101,
                0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 108, 111, 110, 103, 32, 108, 111,
                110, 103, 0, 99, 116, 120, 0, 104, 105, 100, 95, 116, 97, 105, 108, 95, 99, 97,
                108, 108, 0, 102, 109, 111, 100, 95, 114, 101, 116, 47, 95, 95, 104, 105, 100, 95,
                98, 112, 102, 95, 116, 97, 105, 108, 95, 99, 97, 108, 108, 0, 47, 104, 111, 109,
                101, 47, 98, 116, 105, 115, 115, 111, 105, 114, 47, 83, 114, 99, 47, 104, 105, 100,
                47, 100, 114, 105, 118, 101, 114, 115, 47, 104, 105, 100, 47, 98, 112, 102, 47,
                101, 110, 116, 114, 121, 112, 111, 105, 110, 116, 115, 47, 101, 110, 116, 114, 121,
                112, 111, 105, 110, 116, 115, 46, 98, 112, 102, 46, 99, 0, 105, 110, 116, 32, 66,
                80, 70, 95, 80, 82, 79, 71, 40, 104, 105, 100, 95, 116, 97, 105, 108, 95, 99, 97,
                108, 108, 44, 32, 115, 116, 114, 117, 99, 116, 32, 104, 105, 100, 95, 98, 112, 102,
                95, 99, 116, 120, 32, 42, 104, 99, 116, 120, 41, 0, 104, 105, 100, 95, 98, 112,
                102, 95, 99, 116, 120, 0, 105, 110, 100, 101, 120, 0, 104, 105, 100, 0, 97, 108,
                108, 111, 99, 97, 116, 101, 100, 95, 115, 105, 122, 101, 0, 114, 101, 112, 111,
                114, 116, 95, 116, 121, 112, 101, 0, 95, 95, 117, 51, 50, 0, 117, 110, 115, 105,
                103, 110, 101, 100, 32, 105, 110, 116, 0, 104, 105, 100, 95, 114, 101, 112, 111,
                114, 116, 95, 116, 121, 112, 101, 0, 72, 73, 68, 95, 73, 78, 80, 85, 84, 95, 82,
                69, 80, 79, 82, 84, 0, 72, 73, 68, 95, 79, 85, 84, 80, 85, 84, 95, 82, 69, 80, 79,
                82, 84, 0, 72, 73, 68, 95, 70, 69, 65, 84, 85, 82, 69, 95, 82, 69, 80, 79, 82, 84,
                0, 72, 73, 68, 95, 82, 69, 80, 79, 82, 84, 95, 84, 89, 80, 69, 83, 0, 114, 101,
                116, 118, 97, 108, 0, 115, 105, 122, 101, 0, 95, 95, 115, 51, 50, 0, 48, 58, 48, 0,
                9, 98, 112, 102, 95, 116, 97, 105, 108, 95, 99, 97, 108, 108, 40, 99, 116, 120, 44,
                32, 38, 104, 105, 100, 95, 106, 109, 112, 95, 116, 97, 98, 108, 101, 44, 32, 104,
                99, 116, 120, 45, 62, 105, 110, 100, 101, 120, 41, 59, 0, 99, 104, 97, 114, 0, 76,
                73, 67, 69, 78, 83, 69, 0, 46, 109, 97, 112, 115, 0, 108, 105, 99, 101, 110, 115,
                101, 0, 104, 105, 100, 95, 100, 101, 118, 105, 99, 101, 0,
            ],
            header: sys::btf_header {
                magic: 60319,
                version: 1,
                flags: 0,
                hdr_len: 24,
                type_off: 0,
                type_len: 608,
                str_off: 608,
                str_len: 530,
            },
        };
        assert_eq!(btf.name(1).unwrap(), OsStr::new("int"));
    }

    /// Check that we can successfully load the BTF for a BPF program.
    #[test]
    fn btf_loading() {
        let mut obj = test_object("getpid.bpf.o");
        let prog = prog_mut(&mut obj, "handle__getpid");
        let _link = prog
            .attach_tracepoint("syscalls", "sys_enter_getpid")
            .expect("failed to attach prog");

        let prog_id = 0;
        // Given that we just loaded a program, we should be able to find
        // at least one.
        let prog_id = sys::bpf_prog_get_next_id(prog_id).unwrap();
        let fd = sys::bpf_prog_get_fd_from_id(prog_id).unwrap();

        let mut info = sys::bpf_prog_info::default();
        let () = sys::bpf_prog_get_info_from_fd(fd.as_raw_fd(), &mut info).unwrap();

        let _btf = Btf::load_from_id(info.btf_id).unwrap();
    }
}

use std::mem::transmute;
use std::path::Path;
use std::path::PathBuf;

use crate::elf::ElfParser;
use crate::inspect;
use crate::zip;
use crate::Addr;
use crate::Mmap;
use crate::SymType;


/// Find the `the_answer` function inside the provided `mmap`, which is
/// expected to be the memory mapped `libtest-so.so`.
///
/// This function returns the symbol information of the function along
/// with it's absolute address in the memory mapped region.
#[allow(clippy::missing_transmute_annotations)]
pub(crate) fn find_the_answer_fn(mmap: &Mmap) -> (inspect::SymInfo<'static>, Addr) {
    // Look up the address of the `the_answer` function inside of the shared
    // object.
    let elf_parser = ElfParser::from_mmap(mmap.clone(), Some(PathBuf::from("libtest-so.so")));
    let opts = inspect::FindAddrOpts {
        offset_in_file: true,
        sym_type: SymType::Function,
    };
    let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
    // There is only one symbol with this address in there.
    assert_eq!(syms.len(), 1);
    let sym = syms.first().unwrap();

    let the_answer_addr = unsafe { mmap.as_ptr().add(sym.addr as usize) };
    // Now just double check that everything worked out and the function
    // is actually where it was meant to be.
    let the_answer_fn = unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
    let answer = the_answer_fn();
    assert_eq!(answer, 42);

    (sym.to_owned(), the_answer_addr as Addr)
}

pub(crate) fn find_the_answer_fn_in_zip(mmap: &Mmap) -> (inspect::SymInfo<'static>, Addr) {
    let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
    let so = archive
        .entries()
        .find_map(|entry| {
            let entry = entry.unwrap();
            (entry.path == Path::new("libtest-so.so")).then_some(entry)
        })
        .unwrap();

    let elf_mmap = mmap
        .constrain(so.data_offset..so.data_offset + so.data.len() as u64)
        .unwrap();

    let (sym, the_answer_addr) = find_the_answer_fn(&elf_mmap);
    (sym, the_answer_addr)
}


#[cfg(target_os = "linux")]
mod bpf {
    use super::*;

    use libbpf_rs::Map;
    use libbpf_rs::MapCore as _;
    use libbpf_rs::MapMut;
    use libbpf_rs::Object;
    use libbpf_rs::ObjectBuilder;
    use libbpf_rs::OpenObject;
    use libbpf_rs::ProgramMut;
    use libbpf_rs::RingBufferBuilder;

    use crate::util::ReadRaw as _;


    fn test_object_path(object: &str) -> PathBuf {
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("bpf")
            .join(object)
    }

    #[track_caller]
    fn open_test_object(object: &str) -> OpenObject {
        let obj_path = test_object_path(object);
        let obj = ObjectBuilder::default()
            .open_file(obj_path)
            .expect("failed to open object");
        obj
    }

    #[track_caller]
    pub(crate) fn test_object(filename: &str) -> Object {
        open_test_object(filename)
            .load()
            .expect("failed to load object")
    }

    /// Find the BPF map with the given name, panic if it does not exist.
    #[track_caller]
    fn map_mut<'obj>(object: &'obj mut Object, name: &str) -> MapMut<'obj> {
        object
            .maps_mut()
            .find(|map| map.name() == name)
            .unwrap_or_else(|| panic!("failed to find map `{name}`"))
    }

    /// Find the BPF program with the given name, panic if it does not exist.
    #[track_caller]
    pub(crate) fn prog_mut<'obj>(object: &'obj mut Object, name: &str) -> ProgramMut<'obj> {
        object
            .progs_mut()
            .find(|map| map.name() == name)
            .unwrap_or_else(|| panic!("failed to find program `{name}`"))
    }

    /// A helper function for instantiating a `RingBuffer` with a callback meant
    /// to be invoked when `action` is executed and that is intended to
    /// trigger a write to said `RingBuffer` from kernel space, which then
    /// reads a single `u32` from this buffer from user space and returns
    /// it.
    fn with_ringbuffer<F>(map: &Map, action: F) -> Vec<u8>
    where
        F: FnOnce(),
    {
        let mut value = None;
        {
            let callback = |data: &[u8]| {
                value = Some(data.to_vec());
                0
            };

            let mut builder = RingBufferBuilder::new();
            builder.add(map, callback).expect("failed to add ringbuf");
            let ringbuf = builder.build().expect("failed to build");

            let () = action();
            let () = ringbuf.consume().expect("failed to consume ringbuf");
        }

        value.expect("did not receive RingBuffer callback")
    }

    /// Retrieve the address of the `handle__getpid` and `subprogram`
    /// functions in the `getpid.bpf.o` BPF program.
    #[allow(dead_code)]
    pub fn with_bpf_symbolization_target_addrs<F>(f: F)
    where
        F: FnOnce(Addr, Addr),
    {
        let mut obj = test_object("getpid.bpf.o");
        let prog = prog_mut(&mut obj, "handle__getpid");
        let _link = prog
            .attach_tracepoint("syscalls", "sys_enter_getpid")
            .expect("failed to attach prog");

        let map = map_mut(&mut obj, "ringbuf");
        let action = || {
            let _pid = unsafe { libc::getpid() };
        };
        let data = with_ringbuffer(&map, action);
        let mut data = data.as_slice();
        let handle_getpid = data.read_pod::<Addr>().unwrap();
        let subprogram = data.read_pod::<Addr>().unwrap();
        f(handle_getpid, subprogram)
    }
}

#[cfg(target_os = "linux")]
pub use bpf::*;

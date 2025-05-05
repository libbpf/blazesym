//! Supporting dev-only functionality for `blazesym`.

#[cfg(linux)]
mod bpf {
    use std::path::Path;
    use std::path::PathBuf;

    use blazesym::Addr;
    use blazesym::__private::ReadRaw as _;

    use libbpf_rs::Map;
    use libbpf_rs::MapCore as _;
    use libbpf_rs::MapMut;
    use libbpf_rs::Object;
    use libbpf_rs::ObjectBuilder;
    use libbpf_rs::OpenObject;
    use libbpf_rs::ProgramMut;
    use libbpf_rs::RingBufferBuilder;


    fn test_object_path(object: &str) -> PathBuf {
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
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

    /// Find and open the BPF object corresponding to the provided file
    /// name.
    #[track_caller]
    pub fn test_object(filename: &str) -> Object {
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
    pub fn prog_mut<'obj>(object: &'obj mut Object, name: &str) -> ProgramMut<'obj> {
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

#[cfg(linux)]
pub use bpf::*;

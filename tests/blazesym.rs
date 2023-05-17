#![allow(clippy::let_and_return, clippy::let_unit_value)]

use std::ffi::CString;
use std::fs::read as read_file;
use std::io::Error;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;


/// Make sure that we fail symbolization when providing a non-existent source.
#[test]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        symbolize::Source::Gsym(symbolize::Gsym::new(non_existent)),
        symbolize::Source::Elf(symbolize::Elf::new(non_existent)),
    ];
    let symbolizer = Symbolizer::new();

    for src in srcs {
        let err = symbolizer.symbolize(&src, &[0x2000100]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can correctly symbolize an address using GSYM.
#[test]
fn symbolize_gsym() {
    let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test.gsym");

    let src = symbolize::Source::Gsym(symbolize::Gsym::new(test_gsym));
    let symbolizer = Symbolizer::new();

    let results = symbolizer
        .symbolize(&src, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}

/// Check that we can symbolize an address using DWARF.
#[test]
fn symbolize_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}

/// Check that we can symbolize addresses inside our own process.
#[test]
fn symbolize_process() {
    let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
    let addrs = [symbolize_process as Addr, Symbolizer::new as Addr];
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &addrs)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);

    let result = &results[0];
    assert!(result.symbol.contains("symbolize_process"), "{result:x?}");

    let result = &results[1];
    assert!(result.symbol.contains("Symbolizer3new"), "{result:x?}");
}

/// Check that we can normalize user addresses in our own shared object.
#[test]
fn normalize_user_addr() {
    fn test(so: &str) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data").join(so);
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 1);
        assert_eq!(norm_addrs.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let norm_addr = norm_addrs.addrs[0];
        let meta = &norm_addrs.meta[norm_addr.1];
        assert_eq!(meta.binary().unwrap().path, test_so);

        let elf = symbolize::Elf::new(test_so);
        let src = symbolize::Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let results = symbolizer
            .symbolize(&src, &[norm_addr.0])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.symbol, "the_answer");
    }

    test("libtest-so.so");
    test("libtest-so-no-separate-code.so");
}


/// Check that we can look up an address.
#[test]
fn inspect() {
    fn test(src: inspect::Source) {
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&["factorial"], &src)
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.addr, 0x2000100);
        assert_ne!(result.file_offset, 0);
        assert_eq!(
            result.obj_file_name.as_deref().unwrap(),
            src.path().unwrap()
        );
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let src = inspect::Source::Elf(inspect::Elf::new(test_dwarf));
    let () = test(src);

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let mut elf = inspect::Elf::new(test_elf);
    assert!(elf.debug_info);
    elf.debug_info = false;
    let src = inspect::Source::Elf(elf);
    let () = test(src);
}


/// Read four bytes at the given `offset` in the file identified by `path`.
fn read_4bytes_at(path: &Path, offset: u64) -> [u8; 4] {
    let offset = offset as usize;
    let content = read_file(path).unwrap();
    let slice = &content[offset..offset + 4];
    <[u8; 4]>::try_from(slice).unwrap()
}


/// Check that we can correctly retrieve the file offset in an ELF file.
#[test]
fn inspect_file_offset_elf() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&["dummy"], &src)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_ne!(result.file_offset, 0);
    let bytes = read_4bytes_at(src.path().unwrap(), result.file_offset);
    assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
}

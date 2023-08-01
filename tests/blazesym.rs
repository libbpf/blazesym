#![allow(clippy::let_and_return, clippy::let_unit_value)]

use std::env::current_exe;
use std::ffi::CString;
use std::fs::read as read_file;
use std::io::Error;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::ErrorKind;
use blazesym::Pid;

use test_log::test;


/// Make sure that we fail symbolization when providing a non-existent source.
#[test]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        symbolize::Source::from(symbolize::GsymFile::new(non_existent)),
        symbolize::Source::Elf(symbolize::Elf::new(non_existent)),
    ];
    let symbolizer = Symbolizer::default();

    for src in srcs {
        let err = symbolizer.symbolize(&src, &[0x2000100]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Find the size of a function called `name` inside an ELF file `elf`.
fn find_function_size(name: &str, elf: &Path) -> usize {
    let src = inspect::Source::Elf(inspect::Elf::new(elf));
    let inspector = Inspector::new();
    let results = inspector
        .lookup(&[name], &src)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let size = results.first().unwrap().size;
    size
}

/// Check that we can correctly symbolize an address using GSYM.
#[test]
fn symbolize_gsym() {
    fn test(src: symbolize::Source) {
        let symbolizer = Symbolizer::new();

        let results = symbolizer
            .symbolize(&src, &[0x2000100])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000100);
        assert_eq!(result.offset, 0);

        let test_bin = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.bin");
        let size = find_function_size("factorial", &test_bin);
        assert_ne!(size, 0);

        for offset in 1..size {
            let results = symbolizer
                .symbolize(&src, &[0x2000100 + offset])
                .unwrap()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            assert_eq!(results.len(), 1);

            let result = results.first().unwrap();
            assert_eq!(result.name, "factorial");
            assert_eq!(result.addr, 0x2000100);
            assert_eq!(result.offset, offset);
        }
    }

    let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");

    let src = symbolize::Source::from(symbolize::GsymFile::new(&test_gsym));
    test(src);

    let data = read_file(&test_gsym).unwrap();
    let src = symbolize::Source::from(symbolize::GsymData::new(&data));
    test(src);
}

/// Check that we can symbolize an address using DWARF.
#[test]
fn symbolize_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(&test_dwarf));
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.name, "factorial");
    assert_eq!(result.addr, 0x2000100);
    assert_eq!(result.offset, 0);
    assert_eq!(result.line, Some(8));

    // Inquire symbol size.
    let size = find_function_size("factorial", &test_dwarf);
    assert_ne!(size, 0);

    // Now check that we can symbolize addresses at a positive offset from the
    // start of the function.
    for offset in 1..size {
        let results = symbolizer
            .symbolize(&src, &[0x2000100 + offset])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000100);
        assert_eq!(result.offset, offset);
    }
}

/// Check that we can symbolize the `abort_creds` function inside a
/// kernel image properly. Inside of
/// vmlinux-5.17.12-100.fc34.x86_64.dwarf, this function's address range
/// and name are in separate attributes:
/// ```text
/// 0x01273e11: DW_TAG_subprogram
///               DW_AT_abstract_origin     (0x0126ff5d "abort_creds")
///               DW_AT_low_pc      (0xffffffff8110ecb0)
///               DW_AT_high_pc     (0xffffffff8110ecce)
///               DW_AT_frame_base  (DW_OP_call_frame_cfa)
///               DW_AT_call_all_calls      (true)
///               DW_AT_sibling     (0x01273f66)
///
/// 0x0110932c: DW_TAG_subprogram
///               DW_AT_external    (true)
///               DW_AT_name        ("abort_creds")
///               DW_AT_decl_file   ("<...>/include/linux/cred.h")
///               DW_AT_decl_line   (163)
///               DW_AT_decl_column (0x0d)
///               DW_AT_prototyped  (true)
///               DW_AT_declaration (true)
///               DW_AT_sibling     (0x0110933e)
/// ```
/// In the past we were unable to handle this case properly.
#[test]
#[cfg_attr(not(feature = "generate-large-test-files"), ignore)]
fn symbolize_dwarf_complex() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &[0xffffffff8110ecb0])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.addr, 0xffffffff8110ecb0);
    assert_eq!(result.line, Some(534));
}

/// Symbolize a normalized address inside an ELF file, with and without
/// auto-demangling enabled.
#[test]
fn symbolize_elf_demangle() {
    let test_elf = current_exe().unwrap();
    let addr = Normalizer::new as Addr;
    let normalizer = Normalizer::new();
    let norm_addrs = normalizer
        .normalize_user_addrs_sorted(&[addr], Pid::Slf)
        .unwrap();
    let (addr, _meta_idx) = norm_addrs.addrs[0];

    let src = symbolize::Source::Elf(symbolize::Elf::new(test_elf));
    let symbolizer = Symbolizer::builder().enable_demangling(false).build();
    let results = symbolizer
        .symbolize(&src, &[addr])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert!(result.name.contains("Normalizer3new"), "{result:x?}");

    // Do it again, this time with demangling enabled.
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &[addr])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert!(
        result.name == "blazesym::normalize::normalizer::Normalizer::new"
            || result.name == "<blazesym::normalize::normalizer::Normalizer>::new",
        "{}",
        result.name
    );
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
    assert!(result.name.contains("symbolize_process"), "{result:x?}");

    let result = &results[1];
    // It's not entirely clear why we have seen two different demangled
    // symbols, but they both seem legit.
    assert!(
        result.name == "blazesym::symbolize::symbolizer::Symbolizer::new"
            || result.name == "<blazesym::symbolize::symbolizer::Symbolizer>::new",
        "{}",
        result.name
    );
}

/// Check that we can normalize addresses in an ELF shared object.
#[test]
fn normalize_elf_addr() {
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
        assert_eq!(meta.elf().unwrap().path, test_so);

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
        assert_eq!(result.name, "the_answer");
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
        .join("test-stable-addresses-dwarf-only.bin");
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

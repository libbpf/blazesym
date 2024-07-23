#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]
#![cfg_attr(windows, allow(dead_code, unused_imports))]

use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::copy;
use std::fs::read as read_file;
use std::io::Error;
use std::io::Read as _;
use std::io::Write as _;
use std::ops::Deref as _;
#[cfg(not(windows))]
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::str;

use blazesym::helper::read_elf_build_id;
use blazesym::helper::ElfResolver;
use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize::NormalizeOpts;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::ProcessDispatch;
use blazesym::symbolize::ProcessMemberInfo;
use blazesym::symbolize::ProcessMemberType;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Resolve;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::ErrorKind;
use blazesym::Pid;
use blazesym::Result;
use blazesym::SymType;

use scopeguard::defer;

use tempfile::tempdir;
use tempfile::NamedTempFile;

use test_log::test;
use test_tag::tag;


/// Make sure that we fail symbolization when providing a non-existent source.
#[tag(windows)]
#[test]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        symbolize::Source::from(symbolize::GsymFile::new(non_existent)),
        symbolize::Source::Elf(symbolize::Elf::new(non_existent)),
    ];
    let symbolizer = Symbolizer::default();

    for src in srcs {
        let err = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can symbolize an address using ELF, DWARF, and GSYM.
#[tag(windows)]
#[test]
fn symbolize_elf_dwarf_gsym() {
    fn test(src: symbolize::Source, has_code_info: bool) {
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000100);
        assert_eq!(result.offset, 0);

        if has_code_info {
            let code_info = result.code_info.as_ref().unwrap();
            assert_ne!(code_info.dir, None);
            assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
            assert_eq!(code_info.line, Some(10));
        } else {
            assert_eq!(result.code_info, None);
        }

        let size = result.size.unwrap();
        assert_ne!(size, 0);

        // Now check that we can symbolize addresses at a positive offset from the
        // start of the function.
        let offsets = (1..size).collect::<Vec<_>>();
        let addrs = offsets
            .iter()
            .map(|offset| (0x2000100 + offset) as Addr)
            .collect::<Vec<_>>();
        let results = symbolizer
            .symbolize(&src, symbolize::Input::VirtOffset(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), addrs.len());

        for (i, symbolized) in results.into_iter().enumerate() {
            let result = symbolized.into_sym().unwrap();
            assert_eq!(result.name, "factorial");
            assert_eq!(result.addr, 0x2000100);
            assert_eq!(result.offset, offsets[i]);

            if has_code_info {
                let code_info = result.code_info.as_ref().unwrap();
                assert_ne!(code_info.dir, None);
                assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
                assert!(code_info.line.is_some());
            } else {
                assert_eq!(result.code_info, None);
            }
        }
    }

    for file in [
        "test-stable-addrs-no-dwarf.bin",
        "test-stable-addrs-stripped-with-link-to-elf-only.bin",
    ] {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let src = symbolize::Source::Elf(symbolize::Elf::new(path));
        test(src, false);
    }

    for file in [
        "test-stable-addrs-stripped-elf-with-dwarf.bin",
        "test-stable-addrs-lto.bin",
        "test-stable-addrs-compressed-debug-zlib.bin",
        #[cfg(feature = "zstd")]
        "test-stable-addrs-compressed-debug-zstd.bin",
    ] {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let src = symbolize::Source::Elf(symbolize::Elf::new(path));
        test(src, true);
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(&path));
    test(src, true);

    let data = read_file(&path).unwrap();
    let src = symbolize::Source::from(symbolize::GsymData::new(&data));
    test(src, true);
}

/// Check that we correctly symbolize zero sized symbols.
// TODO: Extend this test to more formats.
#[tag(windows)]
#[test]
fn symbolize_zero_size_gsym() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    let src = inspect::Source::Elf(inspect::Elf::new(path));
    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["zero_size"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);
    let zero_size = &results[0];

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(zero_size.addr))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "zero_size");
    assert_eq!(result.addr, zero_size.addr);
    assert_eq!(result.size, Some(0));
}

/// Check that we can symbolize an address using Breakpad.
#[tag(windows)]
#[test]
fn symbolize_breakpad() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let src = symbolize::Source::Breakpad(symbolize::Breakpad::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::FileOffset(0x100))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "factorial");
    assert_eq!(result.addr, 0x100);
    assert_eq!(result.offset, 0);

    let code_info = result.code_info.as_ref().unwrap();
    assert_ne!(code_info.dir, None);
    assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
    assert_eq!(code_info.line, Some(10));

    let size = result.size.unwrap();
    assert_ne!(size, 0);

    let offsets = (1..size).collect::<Vec<_>>();
    let addrs = offsets
        .iter()
        .map(|offset| (0x100 + offset) as Addr)
        .collect::<Vec<_>>();
    let results = symbolizer
        .symbolize(&src, symbolize::Input::FileOffset(&addrs))
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), addrs.len());

    for (i, symbolized) in results.into_iter().enumerate() {
        let result = symbolized.into_sym().unwrap();
        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x100);
        assert_eq!(result.offset, offsets[i]);

        let code_info = result.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
        assert!(code_info.line.is_some());
    }
}

/// Make sure that Breakpad symbol file errors are reported in a
/// somewhat decent fashion.
#[tag(windows)]
#[test]
fn symbolize_breakpad_error() {
    let content = br#"MODULE Linux x86_64 C00D0279606DFBCD53805DDAD2CA66A30 test-stable-addrs.bin
FILE 0 data/test-stable-addrs-cu2.c
PUBLIC 0 0 main
FUNC 34 11 0 factorial_wrapper
34 XXX-this-does-not-belong-here-XXX 4 0
38 a 5 0
42 3 6 0
"#;

    let mut tmpfile = NamedTempFile::new().unwrap();
    let () = tmpfile.write_all(content).unwrap();

    let src = symbolize::Source::Breakpad(symbolize::Breakpad::new(tmpfile.path()));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, symbolize::Input::FileOffset(0x100))
        .unwrap_err();
    assert!(format!("{err:?}").contains("34 XXX-this-does-not-belong-here-XXX 4 0"));
}

/// Check that we can symbolize an address mapping to a variable in an
/// ELF file.
#[tag(windows)]
#[test]
fn symbolize_elf_variable() {
    fn test(debug_syms: bool) {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin");
        let mut elf = symbolize::Elf::new(path);
        elf.debug_syms = debug_syms;
        let src = symbolize::Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x4001100))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "a_variable");
        assert_eq!(result.addr, 0x4001100);
        assert_eq!(result.offset, 0);
        // Even when using DWARF we don't currently support variable lookup,
        // so no matter what, we won't have source code information
        // available at this point.
        assert_eq!(result.code_info, None);

        let size = result.size.unwrap();
        assert_eq!(size, 8);

        let offsets = (1..size).collect::<Vec<_>>();
        let addrs = offsets
            .iter()
            .map(|offset| (0x4001100 + offset) as Addr)
            .collect::<Vec<_>>();
        let results = symbolizer
            .symbolize(&src, symbolize::Input::VirtOffset(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), addrs.len());

        for (i, symbolized) in results.into_iter().enumerate() {
            let result = symbolized.into_sym().unwrap();
            assert_eq!(result.name, "a_variable");
            assert_eq!(result.addr, 0x4001100);
            assert_eq!(result.offset, offsets[i]);
            assert_eq!(result.code_info, None);
        }
    }

    test(false);
    test(true);
}

/// Check that we "fail" symbolization as expected on a stripped ELF
/// binary.
#[tag(windows)]
#[test]
fn symbolize_elf_stripped() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap();

    assert_eq!(result, Symbolized::Unknown(Reason::MissingSyms));
}

/// Make sure that we report (enabled) or don't report (disabled) inlined
/// functions with DWARF and Gsym sources.
#[tag(windows)]
#[test]
fn symbolize_dwarf_gsym_inlined() {
    fn test(src: symbolize::Source, inlined_fns: bool) {
        let symbolizer = Symbolizer::builder()
            .enable_inlined_fns(inlined_fns)
            .build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x200020a))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial_inline_test");
        let code_info = result.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
        // The Gsym format uses inline information to "refine" the
        // line information associated with an address. As a result,
        // when we ignore inline information we may end up with a
        // slightly misleading location, namely that of the deepest
        // inlined caller.
        assert_eq!(code_info.line, Some(if inlined_fns { 34 } else { 23 }));

        if inlined_fns {
            assert_eq!(result.inlined.len(), 2);

            let name = &result.inlined[0].name;
            assert_eq!(*name, "factorial_inline_wrapper");
            let frame = result.inlined[0].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addrs.c"));
            assert_eq!(frame.line, Some(28));

            let name = &result.inlined[1].name;
            assert_eq!(*name, "factorial_2nd_layer_inline_wrapper");
            let frame = result.inlined[1].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addrs.c"));
            assert_eq!(frame.line, Some(23));
        } else {
            assert!(result.inlined.is_empty(), "{:#?}", result.inlined);
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(path));
    test(src.clone(), true);
    test(src, false);

    for file in [
        "test-stable-addrs-stripped-elf-with-dwarf.bin",
        "test-stable-addrs-stripped-with-link.bin",
        "test-stable-addrs-compressed-debug-zlib.bin",
        #[cfg(feature = "zstd")]
        "test-stable-addrs-compressed-debug-zstd.bin",
    ] {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let src = symbolize::Source::from(symbolize::Elf::new(path));
        test(src.clone(), true);
        test(src, false);
    }
}

/// Make sure that we fail loading linked debug information on CRC
/// mismatch.
#[tag(windows)]
#[test]
fn symbolize_dwarf_wrong_debug_link_crc() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-with-link-to-wrong-crc.bin");
    let src = symbolize::Source::from(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("checksum does not match expected one"),
        "{err:?}"
    );
}

/// Check that we do not error out when a debug link does not exist.
#[tag(windows)]
#[test]
fn symbolize_dwarf_non_existent_debug_link() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-with-link-non-existent.bin");
    let src = symbolize::Source::from(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::builder().enable_auto_reload(false).build();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap()
        .into_sym();
    // Because the binary is stripped, we don't expect any symbol
    // resolution.
    assert_eq!(result, None);
}

/// Check that we honor configured debug directories as one would expect.
#[tag(windows)]
#[test]
fn symbolize_configurable_debug_dirs() {
    let dir = tempdir().unwrap();
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-with-link.bin");
    let dst = dir.path().join("test-stable-addrs-stripped-with-link.bin");
    let _count = copy(&path, &dst).unwrap();

    let src = symbolize::Source::from(symbolize::Elf::new(dst));
    let symbolizer = Symbolizer::builder()
        .set_debug_dirs(Option::<[&Path; 0]>::None)
        .set_debug_dirs(Option::<[&Path; 0]>::Some([]))
        .build();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap()
        .into_sym();
    // Shouldn't symbolize to anything because the debug link target cannot be
    // found.
    assert_eq!(result, None);

    let debug_dir1 = tempdir().unwrap();
    let debug_dir2 = tempdir().unwrap();
    let src = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-dwarf-only.dbg");
    let dst = debug_dir2.path().join("test-stable-addrs-dwarf-only.dbg");
    let _count = copy(src, dst).unwrap();

    let src = symbolize::Source::from(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::builder()
        .set_debug_dirs(Some([debug_dir1, debug_dir2]))
        .build();
    let sym = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap()
        .into_sym()
        .unwrap();
    assert_eq!(sym.name, "factorial");
}

/// Make sure that we report (enabled) or don't report (disabled) inlined
/// functions with Breakpad sources.
#[tag(windows)]
#[test]
fn symbolize_breakpad_inlined() {
    fn test(src: symbolize::Source, inlined_fns: bool) {
        let symbolizer = Symbolizer::builder()
            .enable_inlined_fns(inlined_fns)
            .build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::FileOffset(0x20a))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial_inline_test");
        let code_info = result.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
        assert_eq!(code_info.line, Some(if inlined_fns { 34 } else { 23 }));

        if inlined_fns {
            assert_eq!(result.inlined.len(), 2);

            let name = &result.inlined[0].name;
            assert_eq!(*name, "factorial_inline_wrapper");
            let frame = result.inlined[0].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addrs.c"));
            assert_eq!(frame.line, Some(28));

            let name = &result.inlined[1].name;
            assert_eq!(*name, "factorial_2nd_layer_inline_wrapper");
            let frame = result.inlined[1].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addrs.c"));
            assert_eq!(frame.line, Some(23));
        } else {
            assert!(result.inlined.is_empty(), "{:#?}", result.inlined);
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let src = symbolize::Source::from(symbolize::Breakpad::new(path));
    test(src.clone(), true);
    test(src, false);
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
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0xffffffff8110ecb0))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.addr, 0xffffffff8110ecb0);
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}


/// Symbolize an address inside a DWARF file, with and without auto-demangling
/// enabled.
#[tag(windows)]
#[test]
fn symbolize_dwarf_demangle() {
    fn test(test_dwarf: &Path, addr: Addr) -> Result<(), ()> {
        let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
        let symbolizer = Symbolizer::builder().enable_demangling(false).build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert!(
            result.name.contains("test13test_function"),
            "{}",
            result.name
        );

        if result.inlined.is_empty() {
            return Err(())
        }
        assert!(
            result.inlined[0].name.contains("test12inlined_call"),
            "{}",
            result.inlined[0].name
        );

        // Do it again, this time with demangling enabled.
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "test::test_function");
        assert_eq!(result.inlined.len(), 1, "{:#?}", result.inlined);
        assert_eq!(result.inlined[0].name, "test::inlined_call");
        Ok(())
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs.bin");
    let elf = inspect::Elf::new(&test_dwarf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["_RNvCs69hjMPjVIJK_4test13test_function"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(!results.is_empty());

    let addr = results[0].addr;
    let src = symbolize::Source::Elf(symbolize::Elf::new(&test_dwarf));
    let symbolizer = Symbolizer::builder().enable_demangling(false).build();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
        .unwrap()
        .into_sym()
        .unwrap();

    let addr = result.addr;
    let size = result.size.unwrap() as u64;
    for inst_addr in addr..addr + size {
        if test(&test_dwarf, inst_addr).is_ok() {
            return
        }
    }

    panic!("failed to find inlined function call");
}

/// Check that we can symbolize addresses inside our own process.
#[test]
fn symbolize_process() {
    let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
    let addrs = [symbolize_process as Addr, Symbolizer::symbolize as Addr];
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, symbolize::Input::AbsAddr(&addrs))
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);

    let result = results[0].as_sym().unwrap();
    assert!(result.name.contains("symbolize_process"), "{result:x?}");

    let result = results[1].as_sym().unwrap();
    // It's not entirely clear why we have seen two different demangled
    // symbols, but they both seem legit.
    assert!(
        result.name == "blazesym::symbolize::symbolizer::Symbolizer::symbolize"
            || result.name == "<blazesym::symbolize::symbolizer::Symbolizer>::symbolize",
        "{}",
        result.name
    );
}

/// Check that we can symbolize an address in a process using a binary
/// located in a local mount namespace.
#[cfg(not(windows))]
#[test]
fn symbolize_process_in_mount_namespace() {
    use libc::kill;
    use libc::SIGKILL;

    let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let mnt_ns = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-mnt-ns.bin");

    let mut child = Command::new(mnt_ns)
        .arg(test_so)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let pid = child.id();
    defer!({
        // Best effort only. The child may end up terminating gracefully
        // if everything goes as planned.
        // TODO: Ideally this kill would be pid FD based to eliminate
        //       any possibility of killing the wrong entity.
        let _rc = unsafe { kill(pid as _, SIGKILL) };
    });

    let mut buf = [0u8; 64];
    let count = child
        .stdout
        .as_mut()
        .unwrap()
        .read(&mut buf)
        .expect("failed to read child output");
    let addr_str = str::from_utf8(&buf[0..count]).unwrap().trim_end();
    let addr = Addr::from_str_radix(addr_str.trim_start_matches("0x"), 16).unwrap();

    // Make sure to destroy the symbolizer before terminating the child.
    // Otherwise something holds on to a reference and cleanup may fail.
    // TODO: This needs to be better understood.
    {
        let src = symbolize::Source::Process(symbolize::Process::new(Pid::from(child.id())));
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::AbsAddr(addr))
            .unwrap()
            .into_sym()
            .unwrap();
        assert_eq!(result.name, "await_input");
    }

    // "Signal" the child to terminate gracefully.
    let () = child.stdin.as_ref().unwrap().write_all(&[0x04]).unwrap();
    let _status = child.wait().unwrap();
}

/// Test that we can use a custom dispatch function when symbolizing addresses
/// in processes.
#[test]
fn symbolize_process_with_custom_dispatch() {
    fn process_dispatch(info: ProcessMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
        let resolver = match info.member_entry {
            ProcessMemberType::Path(entry) => ElfResolver::open(&entry.maps_file)?,
            _ => unreachable!(),
        };
        Ok(Some(Box::new(resolver)))
    }

    fn process_no_dispatch(_info: ProcessMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
        Ok(None)
    }

    fn test(dispatcher: impl ProcessDispatch + 'static) {
        let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
        let addrs = [
            symbolize_process as Addr,
            symbolize_process_with_custom_dispatch as Addr,
        ];
        let symbolizer = Symbolizer::builder()
            .set_process_dispatcher(dispatcher)
            .build();
        let results = symbolizer
            .symbolize(&src, symbolize::Input::AbsAddr(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 2);

        let result = results[0].as_sym().unwrap();
        assert!(result.name.contains("symbolize_process"), "{result:x?}");

        let result = results[1].as_sym().unwrap();
        assert!(
            result
                .name
                .contains("symbolize_process_with_custom_dispatch"),
            "{result:x?}"
        );
    }

    test(process_dispatch);
    test(process_no_dispatch);
}

/// Check that we can normalize addresses in an ELF shared object.
#[cfg(not(windows))]
#[test]
fn normalize_elf_addr() {
    fn test(so: &str, map_files: bool) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data").join(so);
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());
        defer!({
            let rc = unsafe { libc::dlclose(handle) };
            assert_eq!(rc, 0, "{}", Error::last_os_error());
        });

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let opts = NormalizeOpts {
            sorted_addrs: true,
            map_files,
            ..Default::default()
        };
        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs_opts(Pid::Slf, [the_answer_addr as Addr].as_slice(), &opts)
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        let path = &meta.elf().unwrap().path;
        assert_eq!(
            path.to_str().unwrap().contains("/map_files/"),
            map_files,
            "{path:?}"
        );
        assert_eq!(path.canonicalize().unwrap(), test_so);

        let elf = symbolize::Elf::new(test_so);
        let src = symbolize::Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::FileOffset(output.0))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");

        let results = symbolizer
            .symbolize(&src, symbolize::Input::FileOffset(&[output.0]))
            .unwrap();
        assert_eq!(results.len(), 1);

        let sym = results[0].as_sym().unwrap();
        assert_eq!(sym.name, "the_answer");
    }

    for map_files in [false, true] {
        test("libtest-so.so", map_files);
        test("libtest-so-no-separate-code.so", map_files);
    }
}


/// Check that we can enable/disable the reading of build IDs.
#[cfg(not(windows))]
#[test]
fn normalize_build_id_reading() {
    fn test(read_build_ids: bool) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let opts = NormalizeOpts {
            sorted_addrs: true,
            ..Default::default()
        };
        let normalizer = Normalizer::builder()
            .enable_build_ids(read_build_ids)
            .build();
        let normalized = normalizer
            .normalize_user_addrs_opts(Pid::Slf, [the_answer_addr as Addr].as_slice(), &opts)
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        let elf = meta.elf().unwrap();
        assert_eq!(elf.path, test_so);
        if read_build_ids {
            let expected = read_elf_build_id(&test_so).unwrap().unwrap();
            assert_eq!(elf.build_id.as_ref().unwrap(), &expected);
        } else {
            assert_eq!(elf.build_id, None);
        }
    }

    test(true);
    test(false);
}


/// Check that we can look up an address.
#[test]
fn inspect_elf() {
    fn test(src: inspect::Source, no_vars: bool) {
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["factorial", "a_variable"])
            .unwrap();
        assert_eq!(results.len(), 2);

        let result = &results[0];
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].addr, 0x2000100);
        assert_eq!(result[0].sym_type, SymType::Function);
        assert_ne!(result[0].file_offset, None);
        assert_eq!(
            result[0].obj_file_name.as_deref().unwrap(),
            src.path().unwrap()
        );

        let result = &results[1];
        if no_vars {
            assert!(result.is_empty(), "{result:#x?}");
        } else {
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].addr, 0x4001100);
            assert_eq!(result[0].sym_type, SymType::Variable);
            assert_ne!(result[0].file_offset, None);
            assert_eq!(
                result[0].obj_file_name.as_deref().unwrap(),
                src.path().unwrap()
            );
        }
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
    let src = inspect::Source::Elf(inspect::Elf::new(test_dwarf));
    // Our `DwarfResolver` type does not currently support look up of
    // variables.
    let no_vars = true;
    let () = test(src, no_vars);

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    for debug_syms in [true, false] {
        let mut elf = inspect::Elf::new(&test_elf);
        elf.debug_syms = debug_syms;
        let src = inspect::Source::Elf(elf);
        let () = test(src, false);
    }

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");
    let mut elf = inspect::Elf::new(test_elf);
    assert!(elf.debug_syms);
    elf.debug_syms = false;
    let src = inspect::Source::Elf(elf);
    let () = test(src, false);
}


/// Check that we can look up a symbol by name in a Breakpad file.
#[test]
fn inspect_breakpad() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let breakpad = inspect::Breakpad::new(path);
    let src = inspect::Source::from(breakpad);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["factorial"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let sym = &results[0];
    assert_eq!(sym.name, "factorial");
    assert_eq!(sym.addr, 0x100);
    assert_eq!(sym.sym_type, SymType::Function);
    assert_eq!(sym.file_offset, None);
    assert_eq!(sym.obj_file_name, None);
}


/// Make sure that we can look up a dynamic symbol in an ELF file.
#[test]
fn inspect_elf_dynamic_symbol() {
    #[track_caller]
    fn test(bin: &str) {
        let bin = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(bin);

        let src = inspect::Source::Elf(inspect::Elf::new(&bin));
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["the_answer"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let src = symbolize::Source::Elf(symbolize::Elf::new(&bin));
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(results[0].addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");
        assert_eq!(result.addr, results[0].addr);
    }

    test("libtest-so.so");
    test("libtest-so-stripped.so");
    test("libtest-so-partly-stripped.so");
}

/// Make sure that we can look up an indirect in an ELF file.
#[test]
fn inspect_elf_indirect_function() {
    let bin = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");

    let src = inspect::Source::Elf(inspect::Elf::new(&bin));
    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["indirect_func"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let src = symbolize::Source::Elf(symbolize::Elf::new(&bin));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(results[0].addr))
        .unwrap()
        .into_sym()
        .unwrap();

    // Both functions may legitimately have the same address.
    assert!(["indirect_func", "resolve_indirect_func"].contains(&result.name.deref()));
    assert_eq!(result.addr, results[0].addr);
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
fn inspect_elf_file_offset() {
    fn test(file: &str) {
        let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let elf = inspect::Elf::new(test_elf);
        let src = inspect::Source::Elf(elf);

        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["dummy"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_ne!(result.file_offset, None);
        let bytes = read_4bytes_at(src.path().unwrap(), result.file_offset.unwrap());
        assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
    }

    for file in [
        "test-stable-addrs-no-dwarf.bin",
        "test-stable-addrs-stripped-with-link.bin",
    ] {
        let () = test(file);
    }
}


/// Check that we can iterate over all symbols in an ELF file.
#[test]
fn inspect_elf_breakpad_all_symbols() {
    fn test(src: &inspect::Source) {
        let breakpad = matches!(src, inspect::Source::Breakpad(..));
        let inspector = Inspector::new();
        let mut syms = HashMap::<String, inspect::SymInfo>::new();
        let () = inspector
            .for_each(src, |sym| {
                let _inserted = syms.insert(sym.name.to_string(), sym.to_owned());
            })
            .unwrap();

        // Breakpad doesn't contain any or any reasonable information for
        // some symbols.
        if !breakpad {
            let sym = syms.get("main").unwrap();
            assert_eq!(sym.sym_type, SymType::Function);
        }

        let sym = syms.get("factorial").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        let sym = syms.get("factorial_wrapper").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        let sym = syms.get("factorial_inline_test").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        if !breakpad {
            let sym = syms.get("indirect_func").unwrap();
            assert_eq!(sym.sym_type, SymType::Function);
        }

        let sym = syms.get("my_indirect_func").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        let sym = syms.get("resolve_indirect_func").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        if !breakpad {
            let sym = syms.get("a_variable").unwrap();
            assert_eq!(sym.sym_type, SymType::Variable);
        }
    }

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);
    test(&src);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let breakpad = inspect::Breakpad::new(path);
    let src = inspect::Source::Breakpad(breakpad);
    test(&src);
}


/// Check that we can iterate over all symbols in an ELF file, without
/// encountering duplicates caused by dynamic/static symbol overlap.
#[test]
fn inspect_elf_all_symbols_without_duplicates() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let mut syms = Vec::<String>::new();
    let () = inspector
        .for_each(&src, |sym| {
            let () = syms.push(sym.name.to_string());
        })
        .unwrap();

    assert_eq!(syms.iter().filter(|name| *name == "the_answer").count(), 1);
}

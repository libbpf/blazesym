use std::borrow::Cow;
use std::env;
use std::env::current_exe;
use std::ffi::OsStr;
use std::fs::copy;
use std::fs::metadata;
use std::fs::read as read_file;
use std::fs::remove_file;
use std::fs::set_permissions;
use std::fs::File;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;

use blazesym::helper::ElfResolver;
use blazesym::inspect;
use blazesym::normalize;
use blazesym::symbolize::cache;
use blazesym::symbolize::source::Breakpad;
use blazesym::symbolize::source::Elf;
use blazesym::symbolize::source::GsymData;
use blazesym::symbolize::source::GsymFile;
use blazesym::symbolize::source::Kernel;
use blazesym::symbolize::source::Process;
use blazesym::symbolize::source::Source;
use blazesym::symbolize::ApkDispatch;
use blazesym::symbolize::ApkMemberInfo;
use blazesym::symbolize::FindSymOpts;
use blazesym::symbolize::Input;
use blazesym::symbolize::ProcessDispatch;
use blazesym::symbolize::ProcessMemberInfo;
use blazesym::symbolize::ProcessMemberType;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Resolve;
use blazesym::symbolize::ResolvedSym;
use blazesym::symbolize::Symbolize;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::symbolize::TranslateFileOffset;
use blazesym::Addr;
use blazesym::Error;
use blazesym::ErrorKind;
use blazesym::MaybeDefault;
use blazesym::Mmap;
use blazesym::Pid;
use blazesym::Result;
use blazesym::SymType;
#[cfg(linux)]
use blazesym::__private::find_gettimeofday_in_process;
use blazesym::__private::find_the_answer_fn_in_zip;

#[cfg(linux)]
use blazesym_dev::with_bpf_symbolization_target_addrs;

use rand::Rng as _;
use scopeguard::defer;

use tempfile::tempdir;
use tempfile::NamedTempFile;

use test_fork::fork;
use test_log::test;
use test_tag::tag;

use crate::suite::common::as_user;
use crate::suite::common::non_root_uid;
use crate::suite::common::run_unprivileged_process_test;
#[cfg(linux)]
use crate::suite::common::RemoteProcess;


/// Make sure that we fail symbolization when providing a non-existent source.
#[tag(other_os)]
#[test]
fn symbolize_error_on_non_existent_source() {
    let dir = tempdir().unwrap();
    let non_existent = dir.path().join("does-not-exist");
    let srcs = vec![
        Source::from(GsymFile::new(&non_existent)),
        Source::Elf(Elf::new(&non_existent)),
    ];
    let symbolizer = Symbolizer::default();

    for src in srcs {
        let err = symbolizer
            .symbolize_single(&src, Input::VirtOffset(0x2000200))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can symbolize an address using ELF, DWARF, and GSYM.
#[tag(other_os)]
#[test]
fn symbolize_elf_dwarf_gsym() {
    fn test(src: Source, has_code_info: bool) {
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, Input::VirtOffset(0x2000200))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000200);
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
            .map(|offset| (0x2000200 + offset) as Addr)
            .collect::<Vec<_>>();
        let results = symbolizer
            .symbolize(&src, Input::VirtOffset(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), addrs.len());

        for (i, symbolized) in results.into_iter().enumerate() {
            let result = symbolized.into_sym().unwrap();
            assert_eq!(result.name, "factorial");
            assert_eq!(result.addr, 0x2000200);
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
        "test-stable-addrs-32-no-dwarf.bin",
    ] {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let src = Source::Elf(Elf::new(path));
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
        let src = Source::Elf(Elf::new(path));
        test(src, true);
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.gsym");
    let src = Source::from(GsymFile::new(&path));
    test(src, true);

    let data = read_file(&path).unwrap();
    let src = Source::from(GsymData::new(&data));
    test(src, true);
}


fn symbolize_no_permission_impl(path: &Path) {
    let src = Source::Elf(Elf::new(path));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}


/// Check that we fail symbolization as expected when we don't have the
/// permission to open the symbolization source.
#[cfg(linux)]
#[fork]
#[test]
fn symbolize_elf_no_permission() {
    use libc::getresuid;
    use std::os::unix::fs::PermissionsExt as _;

    // We run as root. Even if we limit permissions for a root-owned file we can
    // still access it (unlike the behavior for regular users). As such, we have
    // to work as a different user to check handling of permission denied
    // errors. Because such a change is process-wide, though, we can't do that
    // directly but have to fork first.
    let mut ruid = 0;
    let mut euid = 0;
    let mut suid = 0;

    let result = unsafe { getresuid(&mut ruid, &mut euid, &mut suid) };
    if result == -1 {
        panic!("failed to get user IDs: {}", io::Error::last_os_error());
    }

    let src = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");

    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path();
    let _bytes = copy(src, path).unwrap();

    let mut permissions = metadata(path).unwrap().permissions();
    // Clear all permissions.
    let () = permissions.set_mode(0o0);
    let () = set_permissions(path, permissions).unwrap();
    let uid = non_root_uid();

    as_user(ruid, uid, || symbolize_no_permission_impl(path))
}

/// Check that we correctly symbolize untyped symbols.
#[tag(other_os)]
#[test]
fn symbolize_elf_no_type() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    let src = inspect::source::Source::Elf(inspect::source::Elf::new(path));
    let inspector = inspect::Inspector::new();
    let results = inspector
        .lookup(&src, &["untyped"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);
    let untyped = &results[0];
    assert_eq!(untyped.sym_type, SymType::Undefined);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    let src = Source::from(Elf::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(untyped.addr))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "untyped");
    assert_eq!(result.addr, untyped.addr);
}

/// Check that we correctly symbolize zero sized symbols.
// TODO: Extend this test to more formats.
#[tag(other_os)]
#[test]
fn symbolize_zero_size_gsym() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    let src = inspect::source::Source::Elf(inspect::source::Elf::new(path));
    let inspector = inspect::Inspector::new();
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
    let src = Source::from(GsymFile::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(zero_size.addr))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "zero_size");
    assert_eq!(result.addr, zero_size.addr);
    assert_eq!(result.size, Some(0));
}

/// Check that we can symbolize an address using Breakpad.
#[tag(other_os)]
#[test]
fn symbolize_breakpad() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let src = Source::Breakpad(Breakpad::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::FileOffset(0x200))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "factorial");
    assert_eq!(
        result.module,
        Some(Cow::Borrowed(OsStr::new("test-stable-addrs.bin")))
    );
    assert_eq!(result.addr, 0x200);
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
        .map(|offset| (0x200 + offset) as Addr)
        .collect::<Vec<_>>();
    let results = symbolizer
        .symbolize(&src, Input::FileOffset(&addrs))
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), addrs.len());

    for (i, symbolized) in results.into_iter().enumerate() {
        let result = symbolized.into_sym().unwrap();
        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x200);
        assert_eq!(result.offset, offsets[i]);

        let code_info = result.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
        assert!(code_info.line.is_some());
    }
}

/// Make sure that Breakpad symbol file errors are reported in a
/// somewhat decent fashion.
#[tag(other_os)]
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

    let src = Source::Breakpad(Breakpad::new(tmpfile.path()));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, Input::FileOffset(0x100))
        .unwrap_err();
    assert!(format!("{err:?}").contains("34 XXX-this-does-not-belong-here-XXX 4 0"));
}

/// Check that we can symbolize an address mapping to a variable in an
/// ELF file.
#[tag(other_os)]
#[test]
fn symbolize_elf_variable() {
    fn test(debug_syms: bool) {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin");
        let mut elf = Elf::new(&path);
        elf.debug_syms = debug_syms;
        let src = Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, Input::VirtOffset(0x4001100))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "a_variable");
        assert_eq!(result.module, Some(Cow::Borrowed(path.as_os_str())));
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
            .symbolize(&src, Input::VirtOffset(&addrs))
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
#[tag(other_os)]
#[test]
fn symbolize_elf_stripped() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped.bin");
    let src = Source::Elf(Elf::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
        .unwrap();

    assert_eq!(result, Symbolized::Unknown(Reason::MissingSyms));
}

/// Check that we can symbolize data in a non-existent ELF binary after
/// caching it.
#[test]
fn symbolize_elf_cached() {
    let dir = tempdir().unwrap();
    let path__ = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    let path = dir.path().join("test-stable-addrs-temporary.bin");
    let _count = copy(&path__, &path).unwrap();

    let symbolizer = Symbolizer::new();

    let test_symbolize = || {
        let src = Source::Elf(Elf::new(&path));
        let result = symbolizer
            .symbolize_single(&src, Input::VirtOffset(0x2000200))
            .unwrap_or_else(|err| panic!("{err:?}"))
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000200);
    };

    let () = symbolizer
        .cache(&cache::Cache::from(cache::Elf::new(&path)))
        .unwrap();

    // Remove the symbolization source and make sure that we can still
    // symbolize.
    let () = remove_file(&path).unwrap();
    let () = test_symbolize();

    // Attempting to cache the entry again should fail, because the file
    // no longer exists.
    let err = symbolizer
        .cache(&cache::Cache::from(cache::Elf::new(&path)))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);

    // And yet, we should still be able to symbolize.
    let () = test_symbolize();
}

/// Make sure that we report (enabled) or don't report (disabled) inlined
/// functions with DWARF and Gsym sources.
#[tag(other_os)]
#[test]
fn symbolize_dwarf_gsym_inlined() {
    fn test(src: Source, inlined_fns: bool) {
        let symbolizer = Symbolizer::builder()
            .enable_inlined_fns(inlined_fns)
            .build();
        let result = symbolizer
            .symbolize_single(&src, Input::VirtOffset(0x200030a))
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
    let src = Source::from(GsymFile::new(path));
    test(src.clone(), true);
    test(src, false);

    for file in [
        "test-stable-addrs-stripped-elf-with-dwarf.bin",
        "test-stable-addrs-stripped-with-link.bin",
        "test-stable-addrs-split-dwarf.bin",
        "test-stable-addrs-compressed-debug-zlib.bin",
        #[cfg(feature = "zstd")]
        "test-stable-addrs-compressed-debug-zstd.bin",
    ] {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let src = Source::from(Elf::new(path));
        test(src.clone(), true);
        test(src, false);
    }
}

/// Check that we correctly determine the symbol's source code directory
/// even if it is not overwritten for the compilation unit that a symbol
/// resides in.
#[test]
fn symbolize_dwarf_without_comp_dir_overwrite() {
    let data_dir = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data");
    let path = data_dir.join("test-empty.bin");

    let src = inspect::source::Source::Elf(inspect::source::Elf::new(&path));
    let inspector = inspect::Inspector::new();
    let results = inspector
        .lookup(&src, &["main"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let addr = results[0].addr;
    let src = Source::Elf(Elf::new(path));
    let symbolizer = Symbolizer::new();
    let sym = symbolizer
        .symbolize_single(&src, Input::VirtOffset(addr))
        .unwrap()
        .into_sym()
        .unwrap();
    let code_info = sym.code_info.as_ref().unwrap();
    assert_eq!(code_info.dir.as_deref(), Some(data_dir.as_path()));
    assert_eq!(code_info.file, OsStr::new("test-empty.c"));
}

/// Make sure that we fail loading linked debug information on CRC
/// mismatch.
#[tag(other_os)]
#[test]
fn symbolize_dwarf_wrong_debug_link_crc() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-with-link-to-wrong-crc.bin");
    let src = Source::from(Elf::new(path));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("checksum does not match expected one"),
        "{err:?}"
    );
}

/// Check that we do not error out when a debug link does not exist.
#[tag(other_os)]
#[test]
fn symbolize_dwarf_non_existent_debug_link() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-with-link-non-existent.bin");
    let src = Source::from(Elf::new(path));
    let symbolizer = Symbolizer::builder().enable_auto_reload(false).build();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
        .unwrap()
        .into_sym();
    // Because the binary is stripped, we don't expect any symbol
    // resolution.
    assert_eq!(result, None);
}

/// Check that we don't error out due to checksum mismatch on
/// self-referential debug link.
#[test]
fn symbolize_dwarf_self_referential_debug_link() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-with-link-to-self.bin");
    let src = Source::from(Elf::new(path));
    let symbolizer = Symbolizer::builder().enable_auto_reload(false).build();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
        .unwrap()
        .into_sym()
        .unwrap();
    assert_eq!(result.name, "factorial");
    assert_eq!(result.addr, 0x2000200);
}

/// Check that we honor configured debug directories as one would expect.
#[tag(other_os)]
#[test]
fn symbolize_configurable_debug_dirs() {
    let dir = tempdir().unwrap();
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-with-link.bin");
    let dst = dir.path().join("test-stable-addrs-stripped-with-link.bin");
    let _count = copy(&path, &dst).unwrap();

    let src = Source::from(Elf::new(dst));
    let symbolizer = Symbolizer::builder()
        .set_debug_dirs(Option::<[&Path; 0]>::None)
        .set_debug_dirs(Option::<[&Path; 0]>::Some([]))
        .build();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
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

    let src = Source::from(Elf::new(&path));
    let symbolizer = Symbolizer::builder()
        .set_debug_dirs(Some([debug_dir1, debug_dir2]))
        .build();
    let sym = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0x2000200))
        .unwrap()
        .into_sym()
        .unwrap();
    assert_eq!(sym.name, "factorial");
    // The module reported should be the original file and not the
    // linked one.
    assert_eq!(sym.module, Some(Cow::Owned(path.into_os_string())));
}

/// Make sure that we report (enabled) or don't report (disabled) inlined
/// functions with Breakpad sources.
#[tag(other_os)]
#[test]
fn symbolize_breakpad_inlined() {
    fn test(src: Source, inlined_fns: bool) {
        let symbolizer = Symbolizer::builder()
            .enable_inlined_fns(inlined_fns)
            .build();
        let result = symbolizer
            .symbolize_single(&src, Input::FileOffset(0x30a))
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
    let src = Source::from(Breakpad::new(path));
    test(src.clone(), true);
    test(src, false);
}

/// Check that we can symbolize the `abort_creds` function inside a
/// vmlinux file properly. Inside of
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
#[cfg_attr(not(has_large_test_files), ignore)]
fn symbolize_dwarf_complex() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = Source::Elf(Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::VirtOffset(0xffffffff8110ecb0))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.addr, 0xffffffff8110ecb0);
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}


/// Symbolize an address inside a DWARF file, with and without auto-demangling
/// enabled.
#[tag(other_os)]
#[test]
fn symbolize_dwarf_demangle() {
    fn test(test_dwarf: &Path, addr: Addr) -> Result<(), ()> {
        let src = Source::Elf(Elf::new(test_dwarf));
        let symbolizer = Symbolizer::builder().enable_demangling(false).build();
        let result = symbolizer
            .symbolize_single(&src, Input::VirtOffset(addr))
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
            .symbolize_single(&src, Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "test::test_function");
        assert_eq!(result.module, Some(Cow::Borrowed(test_dwarf.as_os_str())));
        assert_eq!(result.inlined.len(), 1, "{:#?}", result.inlined);
        assert_eq!(result.inlined[0].name, "test::inlined_call");
        Ok(())
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs.bin");
    let elf = inspect::source::Elf::new(&test_dwarf);
    let src = inspect::source::Source::Elf(elf);

    let inspector = inspect::Inspector::new();
    let results = inspector
        .lookup(&src, &["_RNvCs69hjMPjVIJK_4test13test_function"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let addr = results[0].addr;
    let size = results[0].size.unwrap() as u64;
    for inst_addr in addr..addr + size {
        if test(&test_dwarf, inst_addr).is_ok() {
            return
        }
    }

    panic!("failed to find inlined function call");
}

/// Check that we can symbolize an address with inline function
/// information inside a DWARF package.
#[test]
fn symbolize_rust_dwp() {
    fn test(test_dwarf: &Path, addr: Addr) -> Result<(), ()> {
        let src = Source::Elf(Elf::new(test_dwarf));
        let symbolizer = Symbolizer::new();
        let sym = symbolizer
            .symbolize_single(&src, Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(sym.name, "test::test_function");

        let code_info = sym.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test.rs"));
        assert!(code_info.line.is_some());

        if sym.inlined.is_empty() {
            return Err(())
        }
        assert_eq!(sym.inlined.len(), 1, "{:#?}", sym.inlined);
        let inlined = &sym.inlined[0];
        assert_eq!(inlined.name, "test::inlined_call");
        let code_info = inlined.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test.rs"));
        assert!(code_info.line.is_some());
        Ok(())
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs-split-dwarf.bin");
    let elf = inspect::source::Elf::new(&test_dwarf);
    let src = inspect::source::Source::Elf(elf);

    let inspector = inspect::Inspector::new();
    let results = inspector
        .lookup(&src, &["_RNvCs69hjMPjVIJK_4test13test_function"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(!results.is_empty());

    let addr = results[0].addr;
    let size = results[0].size.unwrap() as u64;
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
    let src = Source::Process(Process::new(Pid::Slf));
    let addrs = [
        symbolize_process as *const () as Addr,
        Symbolizer::symbolize as *const () as Addr,
    ];
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, Input::AbsAddr(&addrs))
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);

    let result = results[0].as_sym().unwrap();
    assert!(result.name.contains("symbolize_process"), "{result:x?}");
    assert_eq!(
        result.module.as_deref(),
        Some(current_exe().unwrap().as_os_str())
    );

    let result = results[1].as_sym().unwrap();
    assert!(
        // We accept this simple symbolization in case the user has
        // only enabled minimal debug information enabled. This is
        // necessary because right now it appears that project-wide
        // debug settings can't overwrite global ones.
        // https://github.com/rust-lang/cargo/issues/16080
        result.name == "symbolize"
            // It's not entirely clear why we have seen two different demangled
            // symbols, but they both seem legit.
            || result.name == "blazesym::symbolize::symbolizer::Symbolizer::symbolize"
            || result.name == "<blazesym::symbolize::symbolizer::Symbolizer>::symbolize",
        "{}",
        result.name
    );
    assert_eq!(
        result.module.as_deref(),
        Some(current_exe().unwrap().as_os_str())
    );
}

/// Check that we can symbolize an address in a process using a binary
/// located in a local mount namespace.
#[cfg(linux)]
#[test]
fn symbolize_process_in_mount_namespace() {
    let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let mnt_ns = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-mnt-ns.bin");

    let () = RemoteProcess::default()
        .arg(&test_so)
        .exec(&mnt_ns, |pid, addr| {
            let src = Source::Process(Process::new(pid));
            let symbolizer = Symbolizer::new();
            let result = symbolizer
                .symbolize_single(&src, Input::AbsAddr(addr))
                .unwrap()
                .into_sym()
                .unwrap();
            assert_eq!(result.name, "await_input");
        });
}

/// Check that we can symbolize addresses from a process that has
/// already exited, based on VMA data cached earlier.
#[cfg(linux)]
#[test]
fn symbolize_process_exited_cached_vmas() {
    let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let wait = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-wait.bin");

    let symbolizer = Symbolizer::new();

    let (pid, addr) = RemoteProcess::default()
        .arg(&test_so)
        .exec(&wait, |pid, addr| {
            // Cache VMA information about the process while it is alive.
            let () = symbolizer
                .cache(&cache::Cache::from(cache::Process::new(pid)))
                .unwrap();
            (pid, addr)
        });

    // By now the process is guaranteed to be dead (modulo PID reuse...).
    let mut process = Process::new(pid);
    // We need to opt out of map file usage, because those files will no
    // longer be present with the process having exited.
    process.map_files = false;

    let test_symbolize = || {
        let src = Source::Process(process.clone());
        let result = symbolizer
            .symbolize_single(&src, Input::AbsAddr(addr))
            .unwrap()
            .into_sym()
            .unwrap();
        assert_eq!(result.name, "await_input");
    };

    let () = test_symbolize();

    // Attempting to cache the entry again should fail, because the
    // process no longer exists.
    let err = symbolizer
        .cache(&cache::Cache::from(cache::Process::new(pid)))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);

    // And yet, we should still be able to symbolize.
    let () = test_symbolize();
}

/// Check that we can symbolize an address residing in a zip archive.
#[test]
fn symbolize_process_zip() {
    fn test(map_files: bool) {
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let mmap = Mmap::builder().exec().open(&test_zip).unwrap();
        let (sym, the_answer_addr) = find_the_answer_fn_in_zip(&mmap);

        // Symbolize the address we just looked up. It should be correctly
        // mapped to the `the_answer` function within our process.
        let mut process = Process::new(Pid::Slf);
        process.map_files = map_files;
        let src = Source::Process(process);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, Input::AbsAddr(the_answer_addr))
            .unwrap()
            .into_sym()
            .unwrap();

        let mut module = test_zip.as_os_str().to_os_string();
        let () = module.push("!/libtest-so.so");

        assert_eq!(result.name, "the_answer");
        assert_eq!(result.module.as_deref(), Some(module.as_os_str()));
        assert_eq!(result.addr, sym.addr);
    }

    for map_files in [false, true] {
        let () = test(map_files);
    }
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
        let src = Source::Process(Process::new(Pid::Slf));
        let addrs = [
            symbolize_process as *const () as Addr,
            symbolize_process_with_custom_dispatch as *const () as Addr,
        ];
        let symbolizer = Symbolizer::builder()
            .set_process_dispatcher(dispatcher)
            .build();
        let results = symbolizer
            .symbolize(&src, Input::AbsAddr(&addrs))
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

/// Test that we symbolize addresses in a vDSO in our process.
#[cfg(linux)]
#[test]
fn symbolize_own_process_vdso() {
    use libc::clock_gettime;
    use libc::gettimeofday;

    let src = Source::Process(Process::new(Pid::Slf));
    // Both functions are typically provided by the vDSO, though there
    // is no guarantee of that.
    let addrs = [
        gettimeofday as *const () as Addr,
        clock_gettime as *const () as Addr,
    ];
    let symbolizer = Symbolizer::new();

    // Symbolize twice, to exercise both cache population and cache
    // usage paths.
    for _ in [0, 1] {
        let results = symbolizer
            .symbolize(&src, Input::AbsAddr(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 2);
        // We always assume that at least `gettimeofday` resides within
        // the vDSO.
        let sym1 = results[0].as_sym().unwrap();
        assert!(sym1.name.ends_with("gettimeofday"), "{sym1:?}");
        assert_eq!(sym1.module, Some(Cow::from(OsStr::new("[vdso]"))));

        let sym2 = results[1].as_sym().unwrap();
        assert!(sym2.name.contains("clock_gettime"), "{sym2:?}");
    }
}

/// Test that we symbolize addresses in a vDSO in a "remote" process.
#[cfg(linux)]
#[test]
fn symbolize_remote_process_vdso() {
    let test_block = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-block.bin");
    let () = RemoteProcess::default().exec(&test_block, |pid, _addr| {
        let addr = find_gettimeofday_in_process(pid);

        let process = Process::new(pid);
        let src = Source::Process(process);
        let symbolizer = Symbolizer::new();
        let sym = symbolizer
            .symbolize_single(&src, Input::AbsAddr(addr))
            .unwrap()
            .into_sym()
            .unwrap();
        assert!(sym.name.ends_with("gettimeofday"), "{sym:?}");
        assert_eq!(sym.module, Some(Cow::from(OsStr::new("[vdso]"))));
    });
}

/// Make sure that we do not fail symbolization when an empty perf
/// map is present.
#[fork]
#[test]
fn symbolize_with_empty_perf_map() {
    let heap = vec![0; 4096];
    let path = format!("/tmp/perf-{}.map", process::id());
    let _file = File::options()
        .create_new(true)
        .write(true)
        .read(true)
        .open(&path)
        .unwrap();
    defer!({
        let _result = remove_file(&path);
    });

    let src = Source::Process(Process::new(Pid::Slf));
    // We attempt symbolization of an address inside the heap, whose
    // corresponding proc maps entry is likely "unnamed". That
    // should trigger the perf map symbolization path, and the perf
    // map that we created above is empty.
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::AbsAddr(heap.as_slice().as_ptr() as Addr))
        .unwrap();
    assert!(matches!(result, Symbolized::Unknown(..)));
}

/// Check that we can symbolize an address using a perf map.
#[cfg(linux)]
#[fork]
#[test]
#[ignore = "test requires python 3.12 or higher"]
fn symbolize_process_perf_map() {
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::BufRead as _;
    use std::io::BufReader;

    let script = r#"
import ctypes
import sys

sys.activate_stack_trampoline("perf")

def main():
  open("/proc/self/fd/1", "wb").write(ctypes.c_uint64(0x0))
  input()
  return 0

if __name__ == "__main__":
  main()
"#;

    let python = env::var_os("PYTHON").unwrap_or_else(|| OsString::from("python"));
    let () = RemoteProcess::default()
        .arg("-c")
        .arg(script)
        .exec(python, |pid, _addr| {
            let path = Path::new("/tmp").join(format!("perf-{pid}.map"));
            let file = BufReader::new(File::open(&path).unwrap());
            let lines = file.lines().collect::<Result<Vec<_>, _>>().unwrap();
            let line = &lines[lines.len() / 2];
            let [addr, size, name] = line.split_ascii_whitespace().collect::<Vec<_>>()[..] else {
                panic!("failed to parse perf map line: `{line}`")
            };
            let addr = Addr::from_str_radix(addr, 16).unwrap();
            let size = usize::from_str_radix(size, 16).unwrap();

            let src = Source::Process(Process::new(pid));
            let symbolizer = Symbolizer::new();

            let addrs = (addr..addr + size as Addr).collect::<Vec<_>>();
            let results = symbolizer
                .symbolize(&src, Input::AbsAddr(&addrs))
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(results.len(), size);
            let () = results.into_iter().for_each(|symbolized| {
                let result = symbolized.into_sym().unwrap();
                assert_eq!(result.name, name);
                assert_eq!(result.addr, addr);
                assert_eq!(result.size, Some(size));
            });
        });
}

fn symbolize_permissionless_impl(pid: Pid, addr: Addr, _test_lib: &Path) {
    let process = Process::new(pid);
    assert!(process.map_files);

    let src = Source::Process(process);
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, Input::AbsAddr(addr))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);

    let mut process = Process::new(pid);
    process.map_files = false;

    let src = Source::Process(process);
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::AbsAddr(addr))
        .unwrap()
        .into_sym()
        .unwrap();
    assert_eq!(result.name, "await_input");
}

/// Check that we can symbolize an address in a process using only
/// symbolic paths.
#[cfg(linux)]
#[fork]
#[test]
fn symbolize_process_symbolic_paths() {
    run_unprivileged_process_test(symbolize_permissionless_impl)
}

/// Check that we can symbolize an address residing in a zip archive, using
/// a custom APK dispatcher.
#[test]
fn symbolize_zip_with_custom_dispatch() {
    fn zip_dispatch(info: ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
        assert_eq!(info.member_path, Path::new("libtest-so.so"));

        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(info.member_path);

        let resolver = ElfResolver::open(test_so)?;
        Ok(Some(Box::new(resolver)))
    }

    fn zip_no_dispatch(info: ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
        assert_eq!(info.member_path, Path::new("libtest-so.so"));
        Ok(None)
    }

    fn test(dispatcher: impl ApkDispatch + 'static) {
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let mmap = Mmap::builder().exec().open(test_zip).unwrap();
        let (sym, the_answer_addr) = find_the_answer_fn_in_zip(&mmap);

        let src = Source::Process(Process::new(Pid::Slf));
        let symbolizer = Symbolizer::builder().set_apk_dispatcher(dispatcher).build();
        let result = symbolizer
            .symbolize_single(&src, Input::AbsAddr(the_answer_addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");
        assert_eq!(result.addr, sym.addr);
    }

    let () = test(zip_dispatch);
    let () = test(zip_no_dispatch);
}

/// Check that we correctly propagate errors induced by a custom APK
/// dispatcher.
#[test]
fn symbolize_zip_with_custom_dispatch_errors() {
    fn zip_error_dispatch(_info: ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
        Err(Error::from(io::Error::new(
            io::ErrorKind::Unsupported,
            "induced error",
        )))
    }

    fn zip_delayed_error_dispatch(_info: ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
        #[derive(Debug)]
        struct Resolver;

        impl Symbolize for Resolver {
            fn find_sym(
                &self,
                _addr: Addr,
                _opts: &FindSymOpts,
            ) -> Result<Result<ResolvedSym<'_>, Reason>> {
                unimplemented!()
            }
        }

        impl TranslateFileOffset for Resolver {
            fn file_offset_to_virt_offset(&self, _file_offset: u64) -> Result<Option<Addr>> {
                Err(Error::from(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "induced error",
                )))
            }
        }

        Ok(Some(Box::new(Resolver)))
    }

    fn test(dispatcher: impl ApkDispatch + 'static) {
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let mmap = Mmap::builder().exec().open(test_zip).unwrap();
        let (_sym, the_answer_addr) = find_the_answer_fn_in_zip(&mmap);

        let src = Source::Process(Process::new(Pid::Slf));
        let symbolizer = Symbolizer::builder().set_apk_dispatcher(dispatcher).build();
        let err = symbolizer
            .symbolize_single(&src, Input::AbsAddr(the_answer_addr))
            .unwrap_err();

        assert_eq!(err.to_string(), "induced error");
    }

    let () = test(zip_error_dispatch);
    let () = test(zip_delayed_error_dispatch);
}

/// Check that we fail symbolization if no kernel symbolization source
/// is provided.
#[test]
fn symbolize_kernel_no_valid_source() {
    let kernel = Kernel {
        kallsyms: MaybeDefault::None,
        vmlinux: MaybeDefault::None,
        kaslr_offset: Some(0),
        ..Default::default()
    };
    let src = Source::Kernel(kernel);
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, Input::AbsAddr(0xc080a470))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert!(
        err.to_string()
            .starts_with("failed to create kernel resolver"),
        "{err:?}"
    );
}

/// Make sure that we fail vmlinux based symbolization if the provided
/// address is less than the KASLR offset.
#[test]
fn symbolize_kernel_vmlinux_invalid_address() {
    let kernel = Kernel {
        kallsyms: MaybeDefault::None,
        vmlinux: MaybeDefault::Some(
            Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("test-stable-addrs.bin"),
        ),
        kaslr_offset: Some(0xffffffff),
        ..Default::default()
    };
    let src = Source::Kernel(kernel);
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, Input::AbsAddr(0xfffffffe))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(
        err.to_string(),
        "address 0xfffffffe is less than KASLR offset (0xffffffff)",
        "{err:?}"
    );
}

/// Test symbolization of a kernel address present in a kallsyms style
/// file.
#[test]
fn symbolize_kernel_kallsyms() {
    fn test(vmlinux: MaybeDefault<PathBuf>) {
        let kernel = Kernel {
            kallsyms: MaybeDefault::from(
                Path::new(&env!("CARGO_MANIFEST_DIR"))
                    .join("data")
                    .join("kallsyms"),
            ),
            vmlinux,
            kaslr_offset: Some(0),
            ..Default::default()
        };
        let src = Source::Kernel(kernel);
        let symbolizer = Symbolizer::new();

        for offset in 0u16..20 {
            let symbolized = symbolizer
                .symbolize_single(&src, Input::AbsAddr(0xc080a470 + Addr::from(offset)))
                .unwrap();
            let init_task_sym = symbolized.into_sym().unwrap();
            assert_eq!(init_task_sym.name, "init_task");
            assert_eq!(init_task_sym.code_info, None);
            assert_eq!(init_task_sym.offset, usize::from(offset));
        }
    }

    test(MaybeDefault::None);
    // Provide a valid "vmlinux" file, but given that it does not
    // contain the address we attempt to symbolize we should end up
    // falling back to using kallsyms.
    test(MaybeDefault::Some(
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin"),
    ));
}

/// Test symbolization of a "kernel" address in an vmlinux ELF file.
#[test]
fn symbolize_kernel_vmlinux() {
    #[track_caller]
    fn test(kernel: Kernel, has_code_info: bool) {
        let src = Source::Kernel(kernel);
        let symbolizer = Symbolizer::new();
        let symbolized = symbolizer
            .symbolize_single(&src, Input::AbsAddr(0x2000200))
            .unwrap();
        let sym = symbolized.into_sym().unwrap();
        assert_eq!(sym.name, "factorial");
        assert_eq!(sym.addr, 0x2000200);

        if has_code_info {
            let code_info = sym.code_info.as_ref().unwrap();
            assert_ne!(code_info.dir, None);
            assert_eq!(code_info.file, OsStr::new("test-stable-addrs.c"));
            assert!(code_info.line.is_some());
        } else {
            assert_eq!(sym.code_info, None);
        }
    }

    let mut src = Kernel {
        kallsyms: MaybeDefault::None,
        // We use a fake vmlinux here for testing purposes, which really
        // is just a regular ELF file.
        vmlinux: MaybeDefault::Some(
            Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("test-stable-addrs.bin"),
        ),
        kaslr_offset: Some(0),
        debug_syms: true,
        ..Default::default()
    };
    // Source has debug syms and we want to use them.
    test(src.clone(), true);

    // Source has debug syms, but we do not want to use them.
    src.debug_syms = false;
    test(src.clone(), false);

    // Source has no debug syms and we do not want to use them.
    src.vmlinux = MaybeDefault::Some(
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin"),
    );
    test(src.clone(), false);

    // Source has no debug syms and we do want to use them.
    src.debug_syms = true;
    test(src.clone(), false);
}

/// Test symbolization of a kernel address using vmlinux and the system
/// KASLR state.
#[test]
#[ignore = "test requires discoverable vmlinux file present"]
fn symbolize_kernel_system_vmlinux() {
    fn find_kernel_syms() -> Vec<(Addr, String)> {
        let mut file = File::open("/proc/kallsyms").unwrap();
        let mut content = String::new();
        let _cnt = file.read_to_string(&mut content).unwrap();
        let mut pairs = content
            .lines()
            .filter_map(|line| {
                let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                let (addr, ty, name, module) = match fields[..] {
                    [addr, ty, name] => (addr, ty, name, None),
                    [addr, ty, name, module] => (addr, ty, name, Some(module)),
                    _ => panic!("encountered unexpected kallsyms line: {line}"),
                };
                if !["D", "T", "t", "W"].contains(&ty) {
                    return None
                }
                // TODO: Eventually we need to support modules.
                if module.is_some() {
                    return None
                }
                let addr = Addr::from_str_radix(addr, 16).unwrap();
                Some((addr, name))
            })
            .collect::<Vec<_>>();
        let () = pairs.sort_by_key(|(addr, _name)| *addr);

        let mut rng = rand::rng();
        let pairs = (0..20)
            .filter_map(|_| {
                let idx = rng.random_range(0..pairs.len());
                let addr = pairs[idx].0;
                // Make sure that this address is unique by checking that the
                // previous and following ones are different. We ignore
                // duplicate addresses (aliases symbols), because
                // symbolization results won't be unambiguous.
                if let Some(idx) = idx.checked_sub(1) {
                    if let Some((addr_, _name)) = pairs.get(idx) {
                        if *addr_ == addr {
                            return None
                        }
                    }
                }
                if let Some(idx) = idx.checked_add(1) {
                    if let Some((addr_, _name)) = pairs.get(idx) {
                        if *addr_ == addr {
                            return None
                        }
                    }
                }
                let name = pairs[idx].1;
                Some((addr, name.to_string()))
            })
            .collect::<Vec<_>>();

        pairs
    }

    let syms = find_kernel_syms();
    let kernel = Kernel {
        kallsyms: MaybeDefault::None,
        ..Default::default()
    };
    let src = Source::Kernel(kernel);
    let symbolizer = Symbolizer::new();
    let symbolized = symbolizer
        .symbolize(
            &src,
            Input::AbsAddr(
                syms.iter()
                    .map(|(addr, _name)| *addr)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        )
        .unwrap();
    assert_eq!(symbolized.len(), syms.len());
    for (i, sym) in symbolized.iter().enumerate() {
        let sym = sym
            .as_sym()
            .unwrap_or_else(|| panic!("failed to symbolize {:x?}", syms[i]));
        // We have seen cases where symbols were suffixed with LLVM
        // specific prefixes in kallsyms but not in the ELF file. But,
        // in all likelihood, that can happen the other way around as
        // well..
        // E.g.,
        //   left: "fanotify_free_mark"
        //   right: "fanotify_free_mark.llvm.12215866716532162847"
        assert!(
            sym.name.starts_with(&syms[i].1) || syms[i].1.starts_with(sym.name.as_ref()),
            "{sym:?} | {:?}",
            syms[i]
        );
    }
}

/// Test symbolization of a kernel address inside a BPF program.
#[cfg(linux)]
#[test]
fn symbolize_kernel_bpf_program() {
    with_bpf_symbolization_target_addrs(|handle_getpid, subprogram| {
        let kernel = Kernel {
            vmlinux: MaybeDefault::None,
            // KASLR offset shouldn't have any effect for BPF program
            // symbolization.
            kaslr_offset: Some(u64::MAX),
            ..Default::default()
        };
        let src = Source::Kernel(kernel);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize(&src, Input::AbsAddr(&[handle_getpid, subprogram]))
            .unwrap();
        let handle_getpid_sym = result[0].as_sym().unwrap();
        assert!(
            handle_getpid_sym.name.ends_with("handle__getpid"),
            "{}",
            handle_getpid_sym.name
        );
        assert_eq!(
            handle_getpid_sym.module,
            Some(Cow::from(OsStr::new("[bpf]")))
        );
        let code_info = handle_getpid_sym.code_info.as_ref().unwrap();
        assert_eq!(code_info.dir, None);
        assert_eq!(
            Path::new(&code_info.file).file_name(),
            Some(OsStr::new("getpid.bpf.c"))
        );
        assert_eq!(code_info.line, Some(33));
        assert_ne!(code_info.column, None);

        let subprogram_sym = result[1].as_sym().unwrap();
        assert!(
            subprogram_sym.name.ends_with("subprogram"),
            "{}",
            subprogram_sym.name
        );
        assert_eq!(subprogram_sym.module, Some(Cow::from(OsStr::new("[bpf]"))));
        let code_info = subprogram_sym.code_info.as_ref().unwrap();
        assert_eq!(code_info.dir, None);
        assert_eq!(
            Path::new(&code_info.file).file_name(),
            Some(OsStr::new("getpid.bpf.c"))
        );
        assert_eq!(code_info.line, Some(15));
        assert_ne!(code_info.column, None);
    })
}

/// Symbolize a normalized address from a binary with an artificially
/// inflated ELF segment.
///
/// This is a regression test for the case that a program header
/// with a memory size greater than file size is located before a
/// program header that would otherwise match the file offset. Refer
/// to commit 1a4e10740652 ("Use file size in file offset -> virtual
/// offset translation").
#[cfg(linux)]
#[test]
fn symbolize_normalized_large_memsize() {
    let test_block = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-block.bin");
    let () = RemoteProcess::default().exec(&test_block, |pid, addr| {
        let normalizer = normalize::Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs(pid, [addr].as_slice())
            .unwrap();

        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);
        let file_offset = normalized.outputs[0].0;

        let elf = Elf::new(&test_block);
        let src = Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let sym = symbolizer
            .symbolize_single(&src, Input::FileOffset(file_offset))
            .unwrap()
            .into_sym()
            .unwrap();
        assert_eq!(sym.name, "_start");
    });
}

/// Make sure that registering an [`ElfResolver`] with a [`Symbolizer`]
/// fails if one is already present for a given path.
#[test]
fn register_an_existing_elfresolver() {
    let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");

    let resolver = Rc::new(ElfResolver::open(&bin_name).unwrap());
    let mut symbolizer = Symbolizer::new();
    let () = symbolizer
        .register_elf_resolver(&bin_name, Rc::clone(&resolver))
        .unwrap();

    let err = symbolizer
        .register_elf_resolver(&bin_name, Rc::clone(&resolver))
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::AlreadyExists);
}

/// Make sure that creating an [`ElfResolver`] from a non-existing file
/// fails with an actual error instead of panicking.
#[test]
fn create_elf_resolver_from_non_existing_path() {
    let path = Path::new("/This/Path/Does.Not/Exist");
    let err = ElfResolver::open(path).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::NotFound);
}

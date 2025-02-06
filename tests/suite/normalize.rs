use std::env;
use std::ffi::CString;
use std::fs::copy;
use std::io;
#[cfg(linux)]
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;
use std::str;

use blazesym::helper::read_elf_build_id;
use blazesym::normalize;
use blazesym::normalize::NormalizeOpts;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::Addr;
use blazesym::Mmap;
use blazesym::Pid;
use blazesym::__private::find_the_answer_fn;
use blazesym::__private::zip;

use scopeguard::defer;

use tempfile::tempdir;

use test_fork::test as forked_test;
use test_log::test;

use crate::suite::common::run_unprivileged_process_test;


/// Check that we detect unsorted input addresses.
#[test]
fn normalize_unsorted_err() {
    let mut addrs = [
        libc::atexit as Addr,
        libc::chdir as Addr,
        libc::fopen as Addr,
    ];
    let () = addrs.sort();
    let () = addrs.swap(0, 1);

    let opts = NormalizeOpts {
        sorted_addrs: true,
        ..Default::default()
    };
    let normalizer = Normalizer::new();
    let err = normalizer
        .normalize_user_addrs_opts(Pid::Slf, addrs.as_slice(), &opts)
        .unwrap_err();
    assert!(err.to_string().contains("are not sorted"), "{err}");
}

/// Check that we handle unknown addresses as expected.
#[test]
fn normalize_unknown_addrs() {
    // The very first page of the address space should never be
    // mapped, so use addresses from there.
    let addrs = [0x500 as Addr, 0x600 as Addr];

    let normalizer = Normalizer::new();
    let normalized = normalizer
        .normalize_user_addrs(Pid::Slf, addrs.as_slice())
        .unwrap();
    assert_eq!(normalized.outputs.len(), 2);
    assert_eq!(normalized.meta.len(), 1);
    assert_eq!(
        normalized.meta[0],
        normalize::Unknown {
            reason: normalize::Reason::Unmapped,
            _non_exhaustive: ()
        }
        .into()
    );
    assert_eq!(normalized.outputs[0].1, 0);
    assert_eq!(normalized.outputs[1].1, 0);
}

/// Check that we can normalize user addresses in our own process.
#[cfg(linux)]
// `libc` on Arm doesn't have `__errno_location`.
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
#[test]
fn normalization_self() {
    fn test(normalizer: &Normalizer) {
        let addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
            normalize_unknown_addrs as Addr,
            normalization_self as Addr,
            normalize::Normalizer::new as Addr,
        ];

        let (errno_idx, _) = addrs
            .iter()
            .enumerate()
            .find(|(_idx, addr)| **addr == libc::__errno_location as Addr)
            .unwrap();

        let normalized = normalizer
            .normalize_user_addrs(Pid::Slf, addrs.as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 6);

        let outputs = &normalized.outputs;
        let meta = &normalized.meta;
        assert_eq!(meta.len(), 2);

        let errno_meta_idx = outputs[errno_idx].1;
        assert!(meta[errno_meta_idx]
            .as_elf()
            .unwrap()
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("libc.so"));
    }

    let normalizer = Normalizer::new();
    test(&normalizer);

    let normalizer = Normalizer::builder().enable_vma_caching(true).build();
    test(&normalizer);
    test(&normalizer);
}

/// Check that we can normalize addresses in an ELF shared object.
#[cfg(linux)]
#[test]
fn normalize_elf_addr() {
    fn test(so: &str, map_files: bool) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data").join(so);
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());
        defer!({
            let rc = unsafe { libc::dlclose(handle) };
            assert_eq!(rc, 0, "{}", io::Error::last_os_error());
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
        let path = &meta.as_elf().unwrap().path;
        assert_eq!(
            path.to_str().unwrap().contains("/map_files/"),
            map_files,
            "{path:?}"
        );
        assert_eq!(path.canonicalize().unwrap(), test_so);

        let elf = symbolize::source::Elf::new(test_so);
        let src = symbolize::source::Source::Elf(elf);
        let symbolizer = symbolize::Symbolizer::new();
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

/// Check that we can normalize user addresses in our own shared object.
#[test]
fn normalize_custom_so() {
    let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");

    let mmap = Mmap::builder().exec().open(&test_so).unwrap();
    let (sym, the_answer_addr) = find_the_answer_fn(&mmap);

    let normalizer = Normalizer::new();
    let normalized = normalizer
        .normalize_user_addrs(Pid::Slf, [the_answer_addr as Addr].as_slice())
        .unwrap();
    assert_eq!(normalized.outputs.len(), 1);
    assert_eq!(normalized.meta.len(), 1);

    let output = normalized.outputs[0];
    assert_eq!(output.0, sym.file_offset.unwrap());
    let meta = &normalized.meta[output.1];
    let expected_elf = normalize::Elf {
        build_id: Some(read_elf_build_id(&test_so).unwrap().unwrap()),
        path: test_so.clone(),
        _non_exhaustive: (),
    };
    assert_eq!(meta, &normalize::UserMeta::Elf(expected_elf));
}

/// Check that we can normalize addresses in our own shared object inside a
/// zip archive.
#[test]
fn normalize_custom_so_in_zip() {
    fn test(so_name: &str) {
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let mmap = Mmap::builder().exec().open(&test_zip).unwrap();
        let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
        let so = archive
            .entries()
            .find_map(|entry| {
                let entry = entry.unwrap();
                (entry.path == Path::new(so_name)).then_some(entry)
            })
            .unwrap();

        let elf_mmap = mmap
            .constrain(so.data_offset..so.data_offset + so.data.len() as u64)
            .unwrap();
        let (sym, the_answer_addr) = find_the_answer_fn(&elf_mmap);

        let opts = NormalizeOpts {
            sorted_addrs: true,
            ..Default::default()
        };
        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs_opts(Pid::Slf, [the_answer_addr as Addr].as_slice(), &opts)
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let expected_offset = so.data_offset + sym.file_offset.unwrap();
        let output = normalized.outputs[0];
        assert_eq!(output.0, expected_offset);
        let meta = &normalized.meta[output.1];
        let expected = normalize::Apk {
            path: test_zip.clone(),
            _non_exhaustive: (),
        };
        assert_eq!(meta, &normalize::UserMeta::Apk(expected));

        // Also symbolize the normalization output.
        let apk = symbolize::source::Apk::new(test_zip);
        let src = symbolize::source::Source::Apk(apk);
        let symbolizer = symbolize::Symbolizer::new();
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

    test("libtest-so.so");
    test("libtest-so-no-separate-code.so");
}

fn test_normalize_deleted_so(use_procmap_query: bool) {
    fn test(use_procmap_query: bool, cache_vmas: bool, cache_build_ids: bool, use_map_files: bool) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let dir = tempdir().unwrap();
        let tmp_so = dir.path().join("libtest-so.so");
        let _count = copy(&test_so, &tmp_so).unwrap();

        let mmap = Mmap::builder().exec().open(&tmp_so).unwrap();
        let (sym, the_answer_addr) = find_the_answer_fn(&mmap);

        // Remove the temporary directory and with it the mapped shared
        // object.
        let () = drop(dir);

        let opts = NormalizeOpts {
            sorted_addrs: false,
            map_files: use_map_files,
            ..Default::default()
        };
        let normalizer = Normalizer::builder()
            .enable_procmap_query(use_procmap_query)
            .enable_vma_caching(cache_vmas)
            .enable_build_id_caching(cache_build_ids)
            .build();
        let normalized = normalizer
            .normalize_user_addrs_opts(Pid::Slf, [the_answer_addr as Addr].as_slice(), &opts)
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let output = normalized.outputs[0];
        assert_eq!(output.0, sym.file_offset.unwrap());
        let meta = &normalized.meta[output.1].as_elf().unwrap();
        let expected_build_id = if use_map_files || use_procmap_query {
            Some(read_elf_build_id(&test_so).unwrap().unwrap())
        } else {
            None
        };

        assert_eq!(meta.build_id, expected_build_id);
    }

    for cache_build_ids in [true, false] {
        for cache_vmas in [true, false] {
            for use_map_files in [true, false] {
                let () = test(
                    use_procmap_query,
                    cache_build_ids,
                    cache_vmas,
                    use_map_files,
                );
            }
        }
    }
}

/// Check that we can normalize user addresses in a shared object
/// that has been deleted already (but is still mapped) without
/// errors.
#[test]
fn normalize_deleted_so_proc_maps() {
    test_normalize_deleted_so(false)
}

/// Check that we can normalize user addresses in a shared object
/// that has been deleted already (but is still mapped) without
/// errors.
#[test]
#[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
fn normalize_deleted_so_ioctl() {
    test_normalize_deleted_so(true)
}

/// Check that we can enable/disable the reading of build IDs.
#[cfg(linux)]
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
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        let elf = meta.as_elf().unwrap();
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

/// Make sure that when using the `map_files` normalization option,
/// we never end up reporting a path referencing "self".
#[test]
fn normalize_no_self_vma_path_reporting() {
    let opts = NormalizeOpts {
        sorted_addrs: true,
        map_files: true,
        ..Default::default()
    };
    let normalizer = Normalizer::new();
    let normalized = normalizer
        .normalize_user_addrs_opts(
            Pid::Slf,
            [normalize_no_self_vma_path_reporting as Addr].as_slice(),
            &opts,
        )
        .unwrap();

    assert_eq!(normalized.outputs.len(), 1);
    assert_eq!(normalized.meta.len(), 1);
    let output = normalized.outputs[0];
    let meta = &normalized.meta[output.1];
    let elf = meta.as_elf().unwrap();
    assert!(!elf.path.to_string_lossy().contains("self"), "{elf:?}");
}

fn normalize_permissionless_impl(pid: Pid, addr: Addr, test_lib: &Path) {
    let normalizer = Normalizer::builder().enable_build_ids(true).build();
    let opts = NormalizeOpts {
        sorted_addrs: false,
        map_files: false,
        _non_exhaustive: (),
    };

    let normalized = normalizer
        .normalize_user_addrs_opts(pid, &[addr], &opts)
        .unwrap();

    let output = normalized.outputs[0];
    let meta = &normalized.meta[output.1].as_elf().unwrap();

    assert_eq!(
        meta.build_id,
        Some(read_elf_build_id(&test_lib).unwrap().unwrap())
    );
}

/// Check that we can normalize an address in a process using only
/// symbolic paths.
#[cfg(linux)]
#[forked_test]
fn normalize_process_symbolic_paths() {
    run_unprivileged_process_test(normalize_permissionless_impl)
}

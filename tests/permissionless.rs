#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]
#![cfg_attr(windows, allow(dead_code, unused_imports))]

#[cfg(not(windows))]
mod common;

use std::io::Error;
use std::io::Read as _;
use std::io::Write as _;
use std::panic::UnwindSafe;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::str;

use blazesym::helper::read_elf_build_id;
use blazesym::normalize::NormalizeOpts;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::ErrorKind;
use blazesym::Pid;

use scopeguard::defer;

use test_log::test;

fn symbolize_permissionless_impl(pid: Pid, addr: Addr, _test_lib: &Path) {
    let process = symbolize::Process::new(pid);
    assert!(process.map_files);

    let src = symbolize::Source::Process(process);
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, symbolize::Input::AbsAddr(addr))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);

    let mut process = symbolize::Process::new(pid);
    process.map_files = false;

    let src = symbolize::Source::Process(process);
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::AbsAddr(addr))
        .unwrap()
        .into_sym()
        .unwrap();
    assert_eq!(result.name, "await_input");
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

#[cfg(not(windows))]
fn run_test<F>(callback_fn: F)
where
    F: FnOnce(Pid, u64, &Path) + UnwindSafe,
{
    use common::as_user;
    use common::non_root_uid;
    use libc::getresuid;
    use libc::kill;
    use libc::SIGKILL;
    use std::os::unix::process::CommandExt as _;

    let uid = non_root_uid();
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
        panic!("failed to get user IDs: {}", Error::last_os_error());
    }

    let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let mnt_ns = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-wait.bin");

    let mut child = Command::new(mnt_ns)
        .arg(&test_so)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .uid(uid)
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
    let pid = Pid::from(child.id());
    let () = as_user(ruid, uid, || callback_fn(pid, addr, &test_so));

    // "Signal" the child to terminate gracefully.
    let () = child.stdin.as_ref().unwrap().write_all(&[0x04]).unwrap();
    let _status = child.wait().unwrap();
}

/// Check that we can symbolize an address in a process using only
/// symbolic paths.
#[cfg(not(windows))]
#[test]
fn symbolize_process_symbolic_paths() {
    run_test(symbolize_permissionless_impl)
}

/// Check that we can normalize an address in a process using only
/// symbolic paths.
#[cfg(not(windows))]
#[test]
fn normalize_process_symbolic_paths() {
    run_test(normalize_permissionless_impl)
}

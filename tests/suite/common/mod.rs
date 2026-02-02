use std::env::current_exe;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Error;
use std::io::Read as _;
use std::io::Write as _;
#[cfg(not(windows))]
use std::os::unix::process::CommandExt as _;
use std::panic::catch_unwind;
use std::panic::UnwindSafe;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use blazesym::Addr;
use blazesym::Pid;
use blazesym::__private::stat;

#[cfg(not(windows))]
use libc::uid_t;
#[cfg(windows)]
#[allow(non_camel_case_types)]
type uid_t = i16;


/// Run a function with a different effective user ID.
#[cfg(linux)]
pub fn as_user<F, R>(ruid: uid_t, euid: uid_t, f: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    use libc::seteuid;

    if unsafe { seteuid(euid) } == -1 {
        panic!(
            "failed to set effective user ID to {euid}: {}",
            Error::last_os_error()
        )
    }

    let result = catch_unwind(f);

    // Make sure that we restore the real user before tearing down,
    // because shut down code may need the original permissions (e.g., for
    // writing down code coverage files or similar).
    if unsafe { seteuid(ruid) } == -1 {
        panic!(
            "failed to restore effective user ID to {ruid}: {}",
            Error::last_os_error()
        )
    }

    result.unwrap()
}

#[cfg(not(linux))]
pub fn as_user<F, R>(_ruid: uid_t, _euid: uid_t, _f: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    unimplemented!()
}

/// Attempt to infer a usable non-root UID on the system.
pub fn non_root_uid() -> uid_t {
    let exe = current_exe().expect("failed to retrieve executable path");
    let stat = stat(&exe).unwrap_or_else(|err| panic!("failed to stat `{exe:?}`: {err}"));
    stat.st_uid
}


/// Helper for launching a process of a binary that emits an address to
/// stdout and waits for input on stdin.
#[cfg(not(windows))]
#[derive(Debug, Default)]
pub struct RemoteProcess {
    args: Vec<OsString>,
    uid: Option<u32>,
}

#[cfg(not(windows))]
impl RemoteProcess {
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn exec<F, R>(self, bin: impl AsRef<OsStr>, f: F) -> R
    where
        F: FnOnce(Pid, Addr) -> R,
    {
        let mut cmd = Command::new(bin);
        cmd.args(self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(uid) = self.uid {
            cmd.uid(uid);
        }
        let mut child = cmd.spawn().unwrap();

        let mut buf = [0u8; size_of::<Addr>()];
        let () = child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut buf)
            .expect("failed to read child output");
        let addr = Addr::from_ne_bytes(buf);

        let result = f(Pid::from(child.id()), addr);

        // "Signal" the child to terminate gracefully.
        let () = child.stdin.as_ref().unwrap().write_all(&[0x04]).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "child process failed with {status}");

        result
    }
}


#[cfg(linux)]
pub fn run_unprivileged_process_test<F>(callback_fn: F)
where
    F: FnOnce(Pid, u64, &Path) + UnwindSafe,
{
    use libc::getresuid;

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
    let wait = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-wait.bin");

    let () = RemoteProcess::default()
        .arg(&test_so)
        .uid(uid)
        .exec(&wait, |pid, addr| {
            let () = as_user(ruid, uid, || callback_fn(pid, addr, &test_so));
        });
}

#[cfg(not(linux))]
pub fn run_unprivileged_process_test<F>(_callback_fn: F)
where
    F: FnOnce(Pid, u64, &Path) + UnwindSafe,
{
    unimplemented!()
}

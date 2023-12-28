use std::convert::Into;
use std::env::current_dir;
use std::env::set_current_dir;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsFd as _;
use std::os::unix::io::AsRawFd as _;
use std::path::PathBuf;
use std::str::FromStr;

use libc::setns;
use libc::CLONE_NEWNS;

use crate::log::warn;
use crate::Error;
use crate::ErrorExt;
use crate::Pid;

fn get_nspid(pid: Pid) -> Result<(Pid, Pid), Error> {
    let fname = format!("/proc/{pid}/status");
    let file = File::open(&fname).with_context(|| format!("faild to open `{fname}`"))?;
    let reader = BufReader::new(file);
    let (mut tgid, mut nstgid) = (pid, pid);
    let mut found = false;

    for line in reader.lines() {
        match line {
            Ok(line) => {
                /* Use tgid if CONFIG_PID_NS is not defined. */
                if let Some(rest) = line.strip_prefix("Tgid:") {
                    if let Some(num) = rest.split_whitespace().next_back() {
                        let id = Pid::from_str(num).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidInput, format!("{e}"))
                        })?;
                        tgid = id;
                        nstgid = id;
                        found = true;
                    }
                }
                if let Some(rest) = line.strip_prefix("NStgid:") {
                    if let Some(num) = rest.split_whitespace().next_back() {
                        nstgid = Pid::from_str(num).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidInput, format!("{e}"))
                        })?;
                        break;
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    if !found {
        warn!("{}", format!("failed to get Tgid/NStgid from {fname}"));
    }
    Ok((tgid, nstgid))
}

fn enter_mntns(nsi: &NsInfo) -> Result<(), Error> {
    if !nsi.need_setns {
        return Ok(());
    }

    // SAFTEY: when `need_setns` is true, `mntns_path` must contains a new ns mnt's `PathBuf`, so it's always safe to unwrap.
    let mntns_path = nsi.mntns_path.as_ref().unwrap();
    let newns = File::open(mntns_path).context("failed to open newns: {mntns_path}")?;
    // SAFTEY: `setns` with the legal file descriptor is always safe to call.
    let rc = unsafe { setns(newns.as_fd().as_raw_fd(), CLONE_NEWNS) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        warn!("setns to {:?} failed, err {}", mntns_path, err);
        return Err(Error::from(err))
    }
    Ok(())
}

pub(crate) struct NsInfo {
    tgid: Pid,
    nstgid: Pid,
    need_setns: bool,
    mntns_path: Option<PathBuf>,
    oldns: File,
    // From https://github.com/torvalds/linux/commit/b01c1f69c8660eaeab7d365cd570103c5c073a02, we see
    // once finished we setns to old namespace, which also sets the current working directory (cwd) to "/",
    // trashing the cwd we had. So adding the current working directory to be part of `NsInfo` and restoring
    // it in the `Drop` call.
    oldcwd: PathBuf,
}
impl NsInfo {
    pub(crate) fn new(pid: Pid) -> Result<Self, Error> {
        let old_stat_path = "/proc/self/ns/mnt";
        let new_stat_path = format!("/proc/{pid}/ns/mnt");
        let old_stat = fs::metadata(old_stat_path).context("failed to stat `/proc/self/ns/mnt`")?;
        let new_stat = fs::metadata(&new_stat_path)
            .with_context(|| format!("failed to stat `/proc/{pid}/ns/mnt`"))?;
        let oldns = File::open(old_stat_path).context("failed to open `/proc/self/ns/mnt`")?;
        let oldcwd = current_dir().context("failed to get current work dir")?;
        let (tgid, nstgid) = get_nspid(pid).context("failed to get nspid for pid {pid}")?;
        let need_setns = old_stat.ino() != new_stat.ino();
        let mntns_path = if need_setns {
            Some(PathBuf::from(new_stat_path))
        } else {
            None
        };
        let nsi = Self {
            tgid,
            nstgid,
            need_setns,
            mntns_path,
            oldns,
            oldcwd,
        };
        #[cfg(not(test))]
        enter_mntns(&nsi)?;
        Ok(nsi)
    }


    pub(crate) fn pid(&self) -> Pid {
        if self.need_setns {
            self.nstgid
        } else {
            self.tgid
        }
    }

    #[cfg(test)]
    pub(crate) fn need_setns(&self) -> bool {
        self.need_setns
    }
}

impl Drop for NsInfo {
    fn drop(&mut self) {
        if !self.need_setns {
            return;
        }
        // SAFTEY: `setns` with the legal file descriptor is always safe to call.
        let rc = unsafe { setns(self.oldns.as_fd().as_raw_fd(), CLONE_NEWNS) };
        if rc < 0 {
            warn!(
                "failed to set mount ns back, err: {}",
                io::Error::last_os_error()
            );
        }
        if let Err(e) = set_current_dir(&self.oldcwd) {
            warn!(
                "{}",
                format!("failed to set current dir to {:?}, err: {e}", self.oldcwd)
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::process;

    #[test]
    fn self_status_parsing() {
        let (tgid, nstgid) = get_nspid(Pid::Slf).unwrap();
        let pid = Pid::from(process::id());
        assert_eq!(tgid, pid);
        assert_eq!(nstgid, pid);
    }

    #[test]
    fn invalid_status_parsing() {
        assert!(get_nspid(Pid::from(u32::MAX)).is_err());
    }

    #[test]
    fn access_same_mnt_ns() {
        let nsi = NsInfo::new(Pid::Slf);
        assert!(nsi.as_ref().is_ok());
        let nsi = nsi.unwrap();
        assert!(!nsi.need_setns());
        assert!(enter_mntns(&nsi).is_ok());
    }
}

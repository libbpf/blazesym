use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::path::PathBuf;

use crate::Addr;


/// An enumeration identifying a process.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Pid {
    Slf,
    Pid(u32),
}

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Slf => write!(f, "self"),
            Self::Pid(pid) => write!(f, "{pid}"),
        }
    }
}


pub(crate) struct LinuxMapsEntry {
    pub loaded_address: Addr,
    pub _end_address: Addr,
    pub mode: u8,
    pub _offset: u64,
    pub path: PathBuf,
}

/// Parse a line of a proc maps file.
fn parse_maps_line<'line>(line: &'line str, pid: Pid) -> Result<LinuxMapsEntry, Error> {
    let full_line = line;

    let split_once = |line: &'line str, component| -> Result<(&'line str, &'line str), Error> {
        line.split_once(|c: char| c.is_ascii_whitespace())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to find {component} in proc maps line: {line}\n{full_line}"),
                )
            })
    };

    // Lines have the following format:
    // address           perms offset  dev   inode      pathname
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
    // a7cb1000-a7cb2000 ---p 00000000 00:00 0
    // a7ed5000-a8008000 r-xp 00000000 03:00 4222       /lib/libc.so.6
    let (address_str, line) = split_once(line, "address range")?;
    let (loaded_str, end_str) = address_str.split_once('-').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed address range in proc maps line: {full_line}"),
        )
    })?;
    let loaded_address = Addr::from_str_radix(loaded_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed start address in proc maps line: {full_line}: {err}"),
        )
    })?;
    let end_address = Addr::from_str_radix(end_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed end address in proc maps line: {full_line}: {err}"),
        )
    })?;

    let (mode_str, line) = split_once(line, "permissions component")?;
    let mode = mode_str
        .chars()
        .fold(0, |mode, c| (mode << 1) | u8::from(c != '-'));

    let (offset_str, line) = split_once(line, "offset component")?;
    let offset = u64::from_str_radix(offset_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("encountered malformed offset component in proc maps line: {full_line}: {err}"),
        )
    })?;

    let (_dev, line) = split_once(line, "device component")?;
    // Note that by design, a path may not be present and so we may not be able
    // to successfully split.
    let path_str = split_once(line, "inode component")
        .map(|(_inode, line)| line.trim())
        .unwrap_or("");
    let path = if path_str.ends_with(" (deleted)") {
        PathBuf::from(format!("/proc/{pid}/map_files/{address_str}"))
    } else {
        PathBuf::from(path_str)
    };

    let entry = LinuxMapsEntry {
        loaded_address,
        _end_address: end_address,
        mode,
        _offset: offset,
        path,
    };
    Ok(entry)
}

fn parse_file<R>(reader: R, pid: Pid) -> Result<Vec<LinuxMapsEntry>, Error>
where
    R: Read,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut entries = Vec::<LinuxMapsEntry>::new();
    while reader.read_line(&mut line)? > 0 {
        let line_str = line.trim();
        // There shouldn't be any empty lines, but we'd just ignore them. We
        // need to trim anyway.
        if !line_str.is_empty() {
            let entry = parse_maps_line(line_str, pid)?;
            entries.push(entry);
        }
        line.clear();
    }

    Ok(entries)
}

/// Parse the maps file for the process with the given PID.
pub(crate) fn parse(pid: Pid) -> Result<Vec<LinuxMapsEntry>, Error> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(path)?;
    parse_file(file, pid)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use test_log::test;


    /// Check that we can parse `/proc/self/maps`.
    #[test]
    fn self_map_parsing() {
        let maps = parse(Pid::Slf).unwrap();
        assert!(!maps.is_empty(), "{}", maps.len());
    }

    #[test]
    fn map_line_parsing() {
        let lines = r#"
55f4a95c9000-55f4a95cb000 r--p 00000000 00:20 41445                      /usr/bin/cat
55f4a95cb000-55f4a95cf000 r-xp 00002000 00:20 41445                      /usr/bin/cat
55f4a95cf000-55f4a95d1000 r--p 00006000 00:20 41445                      /usr/bin/cat
55f4a95d1000-55f4a95d2000 r--p 00007000 00:20 41445                      /usr/bin/cat
55f4a95d2000-55f4a95d3000 rw-p 00008000 00:20 41445                      /usr/bin/cat
55f4aa379000-55f4aa39a000 rw-p 00000000 00:00 0                          [heap]
7f1273b05000-7f1273b06000 r--s 00000000 00:13 19                         /sys/fs/selinux/status
7f2321e00000-7f2321e37000 r--p 00000000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2321e37000-7f2321f6f000 r-xp 00037000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2321f6f000-7f2322009000 r--p 0016f000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2322009000-7f232201b000 r--p 00208000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f232201b000-7f232201d000 rw-p 0021a000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7fa7ade00000-7fa7bb3b7000 r--p 00000000 00:20 12022451                   /usr/lib/locale/locale-archive
7fa7bb400000-7fa7bb428000 r--p 00000000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb428000-7fa7bb59c000 r-xp 00028000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb59c000-7fa7bb5f4000 r--p 0019c000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5f4000-7fa7bb5f8000 r--p 001f3000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5f8000-7fa7bb5fa000 rw-p 001f7000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5fa000-7fa7bb602000 rw-p 00000000 00:00 0
7fa7bb721000-7fa7bb746000 rw-p 00000000 00:00 0
7fa7bb758000-7fa7bb75a000 rw-p 00000000 00:00 0
7fa7bb75a000-7fa7bb75c000 r--p 00000000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb75c000-7fa7bb783000 r-xp 00002000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb783000-7fa7bb78e000 r--p 00029000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb78f000-7fa7bb791000 r--p 00034000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb791000-7fa7bb793000 rw-p 00036000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7ffd03212000-7ffd03234000 rw-p 00000000 00:00 0                          [stack]
7ffd033a7000-7ffd033ab000 r--p 00000000 00:00 0                          [vvar]
7ffd033ab000-7ffd033ad000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
"#;

        let _entries = parse_file(lines.as_bytes(), Pid::Slf).unwrap();

        // Parse the first (actual) line.
        let entry = parse_maps_line(lines.lines().nth(1).unwrap(), Pid::Slf).unwrap();
        assert_eq!(entry.loaded_address, 0x55f4a95c9000);
        assert_eq!(entry._end_address, 0x55f4a95cb000);
        assert_eq!(entry.path, Path::new("/usr/bin/cat"));

        let entry = parse_maps_line(lines.lines().nth(8).unwrap(), Pid::Slf).unwrap();
        assert_eq!(
            entry.path,
            Path::new("/proc/self/map_files/7f2321e00000-7f2321e37000")
        );
    }
}

use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Error;
use std::io::ErrorKind;
use std::path::PathBuf;

use regex::Regex;


pub(crate) struct LinuxMapsEntry {
    pub loaded_address: u64,
    pub _end_address: u64,
    pub mode: u8,
    pub _offset: u64,
    pub path: PathBuf,
}

pub(crate) fn parse(pid: u32) -> Result<Vec<LinuxMapsEntry>, Error> {
    let mut entries = Vec::<LinuxMapsEntry>::new();
    let file_name = if pid == 0 {
        String::from("/proc/self/maps")
    } else {
        format!("/proc/{pid}/maps")
    };
    let file = fs::File::open(file_name)?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let re_ptn = Regex::new(
        r"^([0-9a-f]+)-([0-9a-f]+) ([rwxp\\-]+) ([0-9a-f]+) [0-9a-f]+:[0-9a-f]+ [0-9]+ *((/[^/]+)+)$",
    );
    if re_ptn.is_err() {
        println!("{re_ptn:?}");
        return Err(Error::new(ErrorKind::InvalidData, "Failed to build regex"))
    }
    let re_ptn = re_ptn.unwrap();

    while reader.read_line(&mut line)? > 0 {
        if let Some(caps) = re_ptn.captures(&line) {
            let loaded_address_str = caps.get(1).unwrap().as_str();
            let loaded_address = u64::from_str_radix(loaded_address_str, 16).unwrap();

            let end_address_str = caps.get(2).unwrap().as_str();
            let end_address = u64::from_str_radix(end_address_str, 16).unwrap();

            let mode_str = caps.get(3).unwrap().as_str();
            let mut mode = 0;
            for c in mode_str.chars() {
                mode = (mode << 1) | u8::from(c != '-');
            }

            let offset = u64::from_str_radix(caps.get(4).unwrap().as_str(), 16).unwrap();
            let path = caps.get(5).unwrap().as_str().strip_suffix('\n').unwrap();
            let mut path_str = path.to_string();
            if let Some(pos) = path.rfind(" (deleted)") {
                if pos == path.len() - " (deleted)".len() {
                    path_str = format!("/proc/{pid}/map_files/{loaded_address:x}-{end_address:x}");
                }
            }

            let entry = LinuxMapsEntry {
                loaded_address,
                _end_address: end_address,
                mode,
                _offset: offset,
                path: PathBuf::from(path_str),
            };
            entries.push(entry);
        }
        line.clear();
    }

    Ok(entries)
}

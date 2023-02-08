use std::ffi::CStr;
use std::fs;
use std::io::{BufRead, BufReader, Error, ErrorKind};
use std::path::PathBuf;

use regex::Regex;

pub fn search_address_key<T, V: Ord>(
    data: &[T],
    address: V,
    keyfn: &dyn Fn(&T) -> V,
) -> Option<usize> {
    let mut left = 0;
    let mut right = data.len();

    if right == 0 {
        return None;
    }
    if address < keyfn(&data[0]) {
        return None;
    }

    while (left + 1) < right {
        let v = (left + right) / 2;
        let key = keyfn(&data[v]);

        if key == address {
            return Some(v);
        }
        if address < key {
            right = v;
        } else {
            left = v;
        }
    }

    Some(left)
}

/// Do binary search but skip entries not having a key.
pub fn search_address_opt_key<T, V: Ord>(
    data: &[T],
    address: V,
    keyfn: &dyn Fn(&T) -> Option<V>,
) -> Option<usize> {
    let mut left = 0;
    let mut right = data.len();

    while left < right {
        let left_key = keyfn(&data[left]);
        if left_key.is_some() {
            break;
        }
        left += 1;
    }

    if left == right {
        return None;
    }

    if address < keyfn(&data[left]).unwrap() {
        return None;
    }

    while (left + 1) < right {
        let mut v = (left + right) / 2;

        let v_saved = v;
        // Skip entries not having a key
        while v < right {
            let key = keyfn(&data[v]);
            if key.is_some() {
                break;
            }
            v += 1;
        }
        // All entries at the right side haven't keys.
        // Shrink to the left side.
        if v == right {
            right = v_saved;
            continue;
        }

        let key = keyfn(&data[v]).unwrap();

        if key == address {
            return Some(v);
        }
        if address < key {
            right = v;
        } else {
            left = v;
        }
    }

    Some(left)
}

pub fn extract_string(raw: &[u8], off: usize) -> Option<&str> {
    let mut end = off;

    if off >= raw.len() {
        return None;
    }
    while end < raw.len() && raw[end] != 0 {
        end += 1;
    }
    if end >= raw.len() {
        return None;
    }
    CStr::from_bytes_with_nul(&raw[off..=end])
        .ok()?
        .to_str()
        .ok()
}

pub struct LinuxMapsEntry {
    pub loaded_address: u64,
    pub end_address: u64,
    pub mode: u8,
    pub offset: u64,
    pub path: PathBuf,
}

pub fn parse_maps(pid: u32) -> Result<Vec<LinuxMapsEntry>, Error> {
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
        return Err(Error::new(ErrorKind::InvalidData, "Failed to build regex"));
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
                end_address,
                mode,
                offset,
                path: PathBuf::from(path_str),
            };
            entries.push(entry);
        }
        line.clear();
    }

    Ok(entries)
}

#[inline]
pub fn decode_leb128_128(data: &[u8]) -> Option<(u128, u8)> {
    let mut sz = 0;
    let mut v: u128 = 0;
    for c in data {
        v |= ((c & 0x7f) as u128) << sz;
        sz += 7;
        if (c & 0x80) == 0 {
            return Some((v, sz / 7));
        }
    }
    None
}

#[inline]
pub fn decode_leb128(data: &[u8]) -> Option<(u64, u8)> {
    decode_leb128_128(data).map(|(v, s)| (v as u64, s))
}

pub fn decode_leb128_128_s(data: &[u8]) -> Option<(i128, u8)> {
    if let Some((v, s)) = decode_leb128_128(data) {
        let s_mask: u128 = 1 << (s * 7 - 1);
        return if (v & s_mask) != 0 {
            // negative
            Some(((v as i128) - ((s_mask << 1) as i128), s))
        } else {
            Some((v as i128, s))
        };
    }
    None
}

pub fn decode_leb128_s(data: &[u8]) -> Option<(i64, u8)> {
    decode_leb128_128_s(data).map(|(v, s)| (v as i64, s))
}

#[inline]
pub fn decode_uhalf(data: &[u8]) -> u16 {
    (data[0] as u16) | ((data[1] as u16) << 8)
}

#[cfg(test)]
#[inline]
pub fn decode_shalf(data: &[u8]) -> i16 {
    let uh = decode_uhalf(data);
    if uh >= 0x8000 {
        ((uh as i32) - 0x10000) as i16
    } else {
        uh as i16
    }
}

#[inline]
pub fn decode_uword(data: &[u8]) -> u32 {
    (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16) | ((data[3] as u32) << 24)
}

#[cfg(test)]
#[inline]
pub fn decode_sword(data: &[u8]) -> i32 {
    let uw = decode_uword(data);
    if uw >= 0x80000000 {
        ((uw as i64) - 0x100000000) as i32
    } else {
        uw as i32
    }
}

#[inline]
pub fn decode_udword(data: &[u8]) -> u64 {
    decode_uword(data) as u64 | ((decode_uword(&data[4..]) as u64) << 32)
}

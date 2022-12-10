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

#[allow(dead_code)]
pub struct LinuxMapsEntry {
    pub loaded_address: u64,
    pub end_address: u64,
    pub mode: u8,
    pub offset: u64,
    pub path: PathBuf,
}

#[allow(dead_code)]
pub fn parse_maps(pid: u32) -> Result<Vec<LinuxMapsEntry>, Error> {
    let mut entries = Vec::<LinuxMapsEntry>::new();
    let file_name = if pid == 0 {
        String::from("/proc/self/maps")
    } else {
        format!("/proc/{}/maps", pid)
    };
    let file = fs::File::open(file_name)?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let re_ptn = Regex::new(
        r"^([0-9a-f]+)-([0-9a-f]+) ([rwxp\\-]+) ([0-9a-f]+) [0-9a-f]+:[0-9a-f]+ [0-9]+ *((/[^/]+)+)$",
    );
    if re_ptn.is_err() {
        println!("{:?}", re_ptn);
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
                    path_str = format!(
                        "/proc/{}/map_files/{:x}-{:x}",
                        pid, loaded_address, end_address
                    );
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

#[inline(always)]
pub fn decode_uhalf(data: &[u8]) -> u16 {
    (data[0] as u16) | ((data[1] as u16) << 8)
}

#[cfg(test)]
#[inline(always)]
pub fn decode_shalf(data: &[u8]) -> i16 {
    let uh = decode_uhalf(data);
    if uh >= 0x8000 {
        ((uh as i32) - 0x10000) as i16
    } else {
        uh as i16
    }
}

#[inline(always)]
pub fn decode_uword(data: &[u8]) -> u32 {
    (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16) | ((data[3] as u32) << 24)
}

#[cfg(test)]
#[inline(always)]
pub fn decode_sword(data: &[u8]) -> i32 {
    let uw = decode_uword(data);
    if uw >= 0x80000000 {
        ((uw as i64) - 0x100000000) as i32
    } else {
        uw as i32
    }
}

#[inline(always)]
pub fn decode_udword(data: &[u8]) -> u64 {
    decode_uword(data) as u64 | ((decode_uword(&data[4..]) as u64) << 32)
}

/// Parse basic types from a raw buffer (&[u8]).
///
/// Provide convenient functions to parser basic types from the buffer
/// sequentially.  These data types are used by ELF, DWARF, GSYM,
/// ... and other formats frequently.
///
/// The following is the list of supported types.
///
///  - leb128,
///  - signed leb128,
///  - half word (16-bits),
///  - signed half word (16-bits),
///  - word (32-bits),
///  - signed word (32-bits),
///  - dword (double word; 64-bits),
///  - signed dword (signed double word; 64-bits), and
///  - null terminated string.
///
/// These types are commonly used to define various binary formats,
/// including ELF, DWARF, and GSYM.
pub struct RawBufReader<'a> {
    off: usize,
    data: &'a [u8],
}

impl<'a> RawBufReader<'a> {
    pub fn new(data: &[u8]) -> RawBufReader {
        RawBufReader { off: 0, data }
    }

    //// Ensure there is enough bytes from the current position to the end.
    #[inline]
    fn ensure(&self, len: usize) -> Option<()> {
        if self.data.len() < (self.off + len) {
            return None;
        }
        Some(())
    }

    /// The the offset of the next byte from the beginning of the buffer.
    #[inline]
    pub fn pos(&self) -> usize {
        self.off
    }

    /// The length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// End of stream.
    #[inline]
    pub fn is_eos(&self) -> bool {
        self.off >= self.data.len()
    }

    /// Take the next byte.
    #[inline]
    pub fn take(&mut self) -> u8 {
        let b = self.data[self.off];
        self.off += 1;
        b
    }

    /// Peek the next byte without moving the position.
    #[inline]
    pub fn peek(&mut self) -> u8 {
        self.data[self.off]
    }

    /// Take the next n bytes.
    #[inline]
    pub fn take_slice(&mut self, len: usize) -> Option<&[u8]> {
        self.ensure(len)?;
        let s = &self.data[self.off..(self.off + len)];
        self.off += len;
        Some(s)
    }

    /// Decode a LEB128 number at the current position.
    #[inline]
    pub fn decode_leb128_128(&mut self) -> Option<u128> {
        let mut sz = 0;
        let mut v: u128 = 0;
        for c in &self.data[self.off..] {
            v |= ((c & 0x7f) as u128) << sz;
            sz += 7;
            if sz >= 128 && *c > 3_u8 {
                // 126~132th bits
                // only the first 2-bits (126th & 127th) can be set.
                break;
            }
            if (c & 0x80) == 0 {
                self.off += sz / 7;
                return Some(v);
            }
        }
        None
    }

    /// Decode a LEB128 number at the current position.
    ///
    /// Cast to `u64`.
    #[inline]
    pub fn decode_leb128(&mut self) -> Option<u64> {
        self.decode_leb128_128()?.try_into().ok()
    }

    /// Decode a signed LEB128 number at the current position.
    pub fn decode_leb128_128_s(&mut self) -> Option<i128> {
        let saved_off = self.off;
        if let Some(v) = self.decode_leb128_128() {
            let s = self.off - saved_off;
            let s_mask: u128 = if s > 18 { 1 << 127 } else { 1 << (s * 7 - 1) };
            return if (v & s_mask) != 0 {
                // negative
                let v_mask = s_mask - 1;
                let v = v & v_mask | !v_mask;
                Some(i128::from_ne_bytes(v.to_ne_bytes()))
            } else {
                Some(v as i128)
            };
        }
        None
    }

    /// Decode a signed LEB128 number at the current position.
    ///
    /// Cast to `i64`.
    #[inline]
    pub fn decode_leb128_s(&mut self) -> Option<i64> {
        self.decode_leb128_128_s()?.try_into().ok()
    }

    /// Decode a half word (16-bits).
    #[inline]
    pub fn decode_uhalf(&mut self) -> Option<u16> {
        self.ensure(2)?;
        let data = &self.data[self.off..];
        self.off += 2;
        Some(u16::from_le_bytes(
            data[..2].try_into().expect("slice with incorrect length"),
        ))
    }

    /// Decode a signed half word (16-bits).
    #[cfg(test)]
    #[inline]
    pub fn decode_shalf(&mut self) -> Option<i16> {
        self.ensure(2)?;
        let data = &self.data[self.off..];
        self.off += 2;
        Some(i16::from_le_bytes(
            data[..2].try_into().expect("slice with incorrect length"),
        ))
    }

    /// Decode a word (32-bits).
    #[inline]
    pub fn decode_uword(&mut self) -> Option<u32> {
        self.ensure(4)?;
        let data = &self.data[self.off..];
        self.off += 4;
        Some(u32::from_le_bytes(
            data[..4].try_into().expect("slice with incorrect length"),
        ))
    }

    /// Decode a signed word (32-bits).
    #[cfg(test)]
    #[inline]
    pub fn decode_sword(&mut self) -> Option<i32> {
        self.ensure(4)?;
        let data = &self.data[self.off..];
        self.off += 4;
        Some(i32::from_le_bytes(
            data[..4].try_into().expect("slice with incorrect length"),
        ))
    }

    /// Decode a double word (64-bits).
    #[inline]
    pub fn decode_udword(&mut self) -> Option<u64> {
        self.ensure(8)?;
        let data = &self.data[self.off..];
        self.off += 8;
        Some(u64::from_le_bytes(
            data[..8].try_into().expect("slice with incorrect length"),
        ))
    }

    /// Decode a signed double word (64-bits).
    #[allow(dead_code)]
    #[inline]
    pub fn decode_sdword(&mut self) -> Option<i64> {
        self.ensure(8)?;
        let data = &self.data[self.off..];
        self.off += 8;
        Some(i64::from_le_bytes(
            data[..8].try_into().expect("slice with incorrect length"),
        ))
    }

    /// Extract a string (null terminated) from the current position.
    pub fn extract_string(&mut self) -> Option<&str> {
        let off = self.off;
        let data = self.data;
        let mut end = off;

        if off >= data.len() {
            return None;
        }
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        if end >= data.len() {
            return None;
        }
        self.off = end + 1;
        CStr::from_bytes_with_nul(&data[off..=end])
            .ok()?
            .to_str()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_leb128() {
        // 4 leb numbers (0x1d79f4, -124541, 0, 0)
        let mut data = vec![0xf4, 0xf3, 0x75, 0xf3, 0xf3, 0x72, 0x0, 0x0];
        // a max value for leb128
        data.append(&mut vec![0xff; 18]);
        data.push(0x3);
        // a max value for signed leb128
        data.append(&mut vec![0xff; 18]);
        data.push(0x1);
        // a min value for signed leb128
        data.append(&mut vec![0x80; 18]);
        data.push(0x2);
        // a max (longest) value for signed leb128, it should be -1.
        data.append(&mut vec![0xff; 18]);
        data.push(0x3);
        // a crazy long 0 for leb128.
        data.append(&mut vec![0x80; 18]);
        data.push(0x0);
        // an overflow leb128.
        data.append(&mut vec![0xff; 18]);
        data.push(0x7f);
        // an overflow signed leb128.
        data.append(&mut vec![0xff; 18]);
        data.push(0x7f);
        // a crazy long overflow leb.
        data.append(&mut vec![0xff; 64]);
        data.push(0x0);

        let mut buf = RawBufReader::new(&data);
        assert_eq!(buf.decode_leb128().unwrap(), 0x1d79f4);
        assert_eq!(buf.pos(), 3);

        assert_eq!(buf.decode_leb128_s().unwrap(), -214541);
        assert_eq!(buf.pos(), 6);

        assert_eq!(buf.decode_leb128().unwrap(), 0);
        assert_eq!(buf.pos(), 7);

        assert_eq!(buf.decode_leb128_s().unwrap(), 0);
        assert_eq!(buf.pos(), 8);

        assert_eq!(buf.decode_leb128_128().unwrap(), u128::MAX);
        assert_eq!(buf.decode_leb128_128_s().unwrap(), i128::MAX);
        assert_eq!(buf.decode_leb128_128_s().unwrap(), i128::MIN);
        assert_eq!(buf.decode_leb128_128_s().unwrap(), -1);
        assert_eq!(buf.decode_leb128_128().unwrap(), 0);
        assert_eq!(buf.decode_leb128_128(), None);
        assert_eq!(buf.decode_leb128_128_s(), None);
        assert_eq!(buf.decode_leb128_128(), None);
    }

    #[test]
    fn test_decode_words() {
        let mut data = vec![];
        data.extend_from_slice(&0x857f_u16.to_ne_bytes());
        data.extend_from_slice(&(-1738_i16).to_ne_bytes());
        data.extend_from_slice(&0x789f3f7f_u32.to_ne_bytes());
        data.extend_from_slice(&(-144072897_i32).to_ne_bytes());
        data.extend_from_slice(&0x789f3f7f_u64.to_ne_bytes());
        data.extend_from_slice(&(-144072897_i64).to_ne_bytes());
        let mut buf = RawBufReader::new(&data);
        assert_eq!(buf.decode_uhalf().unwrap(), 0x857f);
        assert_eq!(buf.pos(), 2);
        assert_eq!(buf.decode_shalf().unwrap(), -1738);
        assert_eq!(buf.pos(), 4);
        assert_eq!(buf.decode_uword().unwrap(), 0x789f3f7f);
        assert_eq!(buf.pos(), 8);
        assert_eq!(buf.decode_sword().unwrap(), -144072897);
        assert_eq!(buf.pos(), 12);
        assert_eq!(buf.decode_udword().unwrap(), 0x789f3f7f);
        assert_eq!(buf.pos(), 20);
        assert_eq!(buf.decode_sdword().unwrap(), -144072897);
        assert_eq!(buf.pos(), 28);

        // Check max & min numbers
        let mut data = vec![];
        data.extend_from_slice(&u16::MAX.to_ne_bytes());
        data.extend_from_slice(&u16::MIN.to_ne_bytes());
        data.extend_from_slice(&u32::MAX.to_ne_bytes());
        data.extend_from_slice(&u32::MIN.to_ne_bytes());
        data.extend_from_slice(&u64::MAX.to_ne_bytes());
        data.extend_from_slice(&u64::MIN.to_ne_bytes());
        data.extend_from_slice(&i16::MAX.to_ne_bytes());
        data.extend_from_slice(&i16::MIN.to_ne_bytes());
        data.extend_from_slice(&i32::MAX.to_ne_bytes());
        data.extend_from_slice(&i32::MIN.to_ne_bytes());
        data.extend_from_slice(&i64::MAX.to_ne_bytes());
        data.extend_from_slice(&i64::MIN.to_ne_bytes());
        let mut buf = RawBufReader::new(&data);
        assert_eq!(buf.decode_uhalf().unwrap(), u16::MAX);
        assert_eq!(buf.decode_uhalf().unwrap(), u16::MIN);
        assert_eq!(buf.decode_uword().unwrap(), u32::MAX);
        assert_eq!(buf.decode_uword().unwrap(), u32::MIN);
        assert_eq!(buf.decode_udword().unwrap(), u64::MAX);
        assert_eq!(buf.decode_udword().unwrap(), u64::MIN);
        assert_eq!(buf.decode_shalf().unwrap(), i16::MAX);
        assert_eq!(buf.decode_shalf().unwrap(), i16::MIN);
        assert_eq!(buf.decode_sword().unwrap(), i32::MAX);
        assert_eq!(buf.decode_sword().unwrap(), i32::MIN);
        assert_eq!(buf.decode_sdword().unwrap(), i64::MAX);
        assert_eq!(buf.decode_sdword().unwrap(), i64::MIN);
    }
}

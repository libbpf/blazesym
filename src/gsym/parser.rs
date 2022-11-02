//! Parser of GSYM format.
//!
//! The layout of a standalone GSYM contains following sections in the order.
//!
//! * Header
//! * Address Table
//! * Address Data Offset Table
//! * File Table
//! * String Table
//! * Address Data
//!
//! The standalone GSYM starts with a Header, which describes the
//! size of an entry in the address table, the number of entries in
//! the address table, and the location and the size of the string
//! table.
//!
//! Since the Address Table is immediately after the Header, the
//! Header describes only the size of an entry and number of entries
//! in the table but not where it is.  The Address Table comprises
//! addresses of symbols in the ascending order, so we can find the
//! symbol an address belonging to by doing a binary search to find
//! the most close address but smaller or equal.
//!
//! The Address Data Offset Table has the same number of entries as
//! the Address Table.  Every entry in one table will has
//! corresponding entry at the same offset in the other table.  The
//! entries in the Address Data Offset Table are always 32bits
//! (4bytes.)  It is the file offset to the respective Address
//! Data. (AddressInfo actually)
//!
//! An AddressInfo comprises the size and name of a symbol.  The name
//! is an offset in the string table.  You will find a null terminated
//! C string at the give offset.  The size is the number of bytes of
//! the respective object; ex, a function or variable.
//!
//! See https://reviews.llvm.org/D53379
use super::types::*;

use std::io::{Error, ErrorKind};

use crate::tools::{decode_leb128, decode_leb128_s, decode_udword, decode_uhalf, decode_uword};
use std::ffi::CStr;

/// Hold the major parts of a standalone GSYM file.
///
/// GsymContext provides functions to access major entities in GSYM.
/// GsymContext can find respective AddressInfo for an address.  But,
/// it doesn't parse AddressData to get line numbers.
///
/// The developers should use [`parse_address_data()`],
/// [`parse_line_table_header()`], and [`linetab::run_op()`] to get
/// line number information from [`AddressInfo`].
pub struct GsymContext<'a> {
    header: Header,
    addr_tab: &'a [u8],
    addr_data_off_tab: &'a [u8],
    file_tab: &'a [u8],
    str_tab: &'a [u8],
    raw_data: &'a [u8],
}

impl<'a> GsymContext<'a> {
    /// Parse the Header of a standalone GSYM file.
    ///
    /// # Arguments
    ///
    /// * `data` - is the content of a standalone GSYM.
    ///
    /// Returns a GsymContext, which includes the Header and other important tables.
    pub fn parse_header<'d>(data: &'d [u8]) -> Result<GsymContext<'d>, Error> {
        let mut off = 0;
        // Parse Header
        let magic = decode_uword(data);
        if magic != GSYM_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "invalid magic number"));
        }
        off += 4;
        let version = decode_uhalf(&data[off..]);
        if version != GSYM_VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "unknown version number"));
        }
        off += 2;
        let addr_off_size = data[off];
        off += 1;
        let uuid_size = data[off];
        off += 1;
        let base_address = decode_udword(&data[off..]);
        off += 8;
        let num_addrs = decode_uword(&data[off..]);
        off += 4;
        let strtab_offset = decode_uword(&data[off..]);
        off += 4;
        let strtab_size = decode_uword(&data[off..]);
        off += 4;
        let uuid: [u8; 20] = (&data[off..(off + 20)])
            .try_into()
            .expect("input data is too short");
        off += 20;

        // Get the slices of the Address Table, Address Data Offset Table,
        // and String table.
        let end_off = off + num_addrs as usize * addr_off_size as usize;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (address table)",
            ));
        }
        let addr_tab = &data[off..end_off];
        off += num_addrs as usize * addr_off_size as usize;
        let end_off = off + num_addrs as usize * 4;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (address data offset table)",
            ));
        }
        let addr_data_off_tab = &data[off..end_off];
        off += num_addrs as usize * 4;
        let file_num = decode_uword(&data[off..]);
        off += 4;
        let end_off = off + file_num as usize * 8;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (file table)",
            ));
        }
        let file_tab = &data[off..end_off];
        let end_off = strtab_offset as usize + strtab_size as usize;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (string table)",
            ));
        }
        let str_tab = &data[strtab_offset as usize..end_off];

        Ok(GsymContext {
            header: Header {
                magic,
                version,
                addr_off_size,
                uuid_size,
                base_address,
                num_addrs,
                strtab_offset,
                strtab_size,
                uuid,
            },
            addr_tab,
            addr_data_off_tab,
            file_tab,
            str_tab,
            raw_data: data,
        })
    }

    #[inline(always)]
    pub fn num_addresses(&self) -> usize {
        self.header.num_addrs as usize
    }

    /// Get the address of the an entry in the Address Table.
    ///
    /// # Saftety
    ///
    /// The code will crash with an invalid index.
    #[inline(always)]
    pub fn addr_at(&self, idx: usize) -> u64 {
        assert!(idx < self.header.num_addrs as usize, "invalid index");
        let off = idx * self.header.addr_off_size as usize;
        let mut addr = 0u64;
        let mut shift = 0;
        for d in &self.addr_tab[off..(off + self.header.addr_off_size as usize)] {
            addr |= (*d as u64) << shift;
            shift += 8;
        }
        addr += self.header.base_address;
        addr
    }

    /// Get the AddressInfo of an address given by an index.
    ///
    /// # Saftety
    ///
    /// The code will crash with an invalid index.
    #[inline(always)]
    pub fn addr_info(&self, idx: usize) -> AddressInfo {
        assert!(idx < self.header.num_addrs as usize, "invalid index");
        let off = idx * 4;
        let ad_off = decode_uword(&self.addr_data_off_tab[off..]) as usize;
        let size = decode_uword(&self.raw_data[ad_off..]);
        let name = decode_uword(&self.raw_data[ad_off + 4..]);
        AddressInfo {
            size,
            name,
            data: &self.raw_data[ad_off + 8..],
        }
    }

    /// Get the string at the given offset from the String Table.
    ///
    /// # Saftety
    ///
    /// The code will crash with an invalid offset.
    #[inline(always)]
    pub fn get_str(&self, off: usize) -> &str {
        assert!(self.str_tab[self.str_tab.len() - 1] == 0);
        assert!(off < self.str_tab.len());
        unsafe {
            CStr::from_ptr((&self.str_tab[off..]).as_ptr() as *const i8)
                .to_str()
                .unwrap()
        }
    }

    #[inline(always)]
    pub fn file_info(&self, idx: usize) -> FileInfo {
        assert!(idx < (self.file_tab.len() / 8));
        let mut off = idx * 8;
        let directory = decode_uword(&self.file_tab[off..(off + 4)]);
        off += 4;
        let filename = decode_uword(&self.file_tab[off..(off + 4)]);
        FileInfo {
            directory,
            filename,
        }
    }
}

/// Find the index of an entry in the address table most likely
/// containing the given address.
///
/// The callers should check the respective `AddressInfo` to make sure
/// it is what they request for.
pub fn find_address(ctx: &GsymContext, addr: u64) -> usize {
    let mut left = 0;
    let mut right = ctx.num_addresses();

    if right == 0 {
        return 0;
    }
    if addr < ctx.addr_at(0) {
        return 0;
    }

    while (left + 1) < right {
        let v = (left + right) / 2;
        let cur_addr = ctx.addr_at(v);

        if addr == cur_addr {
            return v;
        }
        if addr < cur_addr {
            right = v;
        } else {
            left = v;
        }
    }
    left
}

/// Parse AddressData.
///
/// AddressDatas are items following AndressInfo.
/// [`GsymContext::addr_info()`] returns the raw data of AddressDatas as a
/// slice at [`AddressInfo::data`].
///
/// # Arguments
///
/// * `data` - is the slice from AddressInfo::data.
///
/// Returns a vector of [`AddressData`].
pub fn parse_address_data(data: &[u8]) -> Vec<AddressData> {
    let mut data_objs = vec![];

    let mut off = 0;
    while off < data.len() {
        let typ = decode_uword(&data[off..]);
        off += 4;
        let length = decode_uword(&data[off..]);
        off += 4;
        let d = &data[off..(off + length as usize)];
        data_objs.push(AddressData {
            typ,
            length,
            data: d,
        });
        off += length as usize;

        #[allow(non_upper_case_globals)]
        match typ {
            InfoTypeEndOfList => {
                break;
            }
            InfoTypeLineTableInfo | InfoTypeInlineInfo => {}
            _ => {
                eprintln!("unknown info type");
            }
        }
    }

    data_objs
}

/// Parse AddressData of InfoTypeLineTableInfo.
///
/// An `AddressData` of `InfoTypeLineTableInfo` type is a table of
/// line numbers for a symbol.  AddressData is the payload of
/// `AddressInfo`.  One AddressInfo may have several AddressData
/// entries in its payload.  Each AddressData entry stores a type of
/// data relates to the symbol the `AddressInfo` presents.
///
/// # Arguments
///
/// * `data` - is what [`AddressData::data`] is.
///
/// Return the `LineTableHeader` and the size of the header of a
/// `AddressData` entry of InfoTypeLineTableInfo type in the payload
/// of an `Addressinfo`.
pub fn parse_line_table_header(data: &[u8]) -> Result<(LineTableHeader, usize), Error> {
    let mut off = 0;
    let (min_delta, bytes) = decode_leb128_s(&data[off..])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse a leb128"))?;
    off += bytes as usize;
    let (max_delta, bytes) = decode_leb128_s(&data[off..])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse a leb128"))?;
    off += bytes as usize;
    let (first_line, bytes) = decode_leb128(&data[off..])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse an unsigned leb128"))?;
    off += bytes as usize;
    Ok((
        LineTableHeader {
            min_delta,
            max_delta,
            first_line: first_line as u32,
        },
        off,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::linetab::{run_op, RunResult};
    use super::super::types::*;
    use super::*;
    use std::env;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    #[test]
    fn test_parse_context() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        // data/test.gsym is generated by running gsymutil on the test
        // case runner at target/debug/deps/blazesym-xxxx, which is
        // generated by cargo for BlazeSym.
        let test_gsym = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        gsym_fo.read_to_end(&mut data).unwrap();
        let ctx = GsymContext::parse_header(&data).unwrap();

        assert_eq!(ctx.addr_at(1), 0x57280);
        let addrinfo = ctx.addr_info(1);
        assert_eq!(
            ctx.get_str(addrinfo.name as usize),
            "_ZN4core9panicking13assert_failed17h40197e8efbe085fbE"
        );

        let idx = ctx.num_addresses() / 3;
        assert_eq!(ctx.addr_at(idx), 0x147c30);
        let addrinfo = ctx.addr_info(idx);
        assert_eq!(ctx.get_str(addrinfo.name as usize), "_ZN81_$LT$std..collections..hash..map..DefaultHasher$u20$as$u20$core..hash..Hasher$GT$5write17h5ed230f0269141d6E");

        let idx = find_address(&ctx, 0x147c30);
        assert_eq!(idx, ctx.num_addresses() / 3);

        let idx = ctx.num_addresses() * 3 / 5;
        assert_eq!(ctx.addr_at(idx), 0x215ee0);
        let addrinfo = ctx.addr_info(idx);
        assert_eq!(
            ctx.get_str(addrinfo.name as usize),
            "_ZN12aho_corasick6packed5teddy7compile4Mask5lo25617ha79c5ff74f3d4cfdE"
        );

        let idx = find_address(&ctx, 0x215ee0);
        assert_eq!(idx, ctx.num_addresses() * 3 / 5);

        let idx = ctx.num_addresses() * 4 / 5;
        assert_eq!(ctx.addr_at(idx), 0x29bda0);
        let addrinfo = ctx.addr_info(idx);
        assert_eq!(ctx.get_str(addrinfo.name as usize), "_ZN83_$LT$alloc..vec..set_len_on_drop..SetLenOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h94a74ddc4127f19aE");

        let addrdata_objs = parse_address_data(addrinfo.data);
        assert_eq!(addrdata_objs.len(), 2);
        let mut has_line_info = false;
        for o in addrdata_objs {
            if o.typ == InfoTypeLineTableInfo {
                let hdr = parse_line_table_header(o.data);
                if let Ok((hdr, bytes)) = hdr {
                    let mut ltctx = LineTableRow {
                        address: 0x29bda0,
                        file_idx: 1,
                        file_line: hdr.first_line,
                    };
                    let ops = &o.data[bytes..];
                    let mut pc = 0;
                    let mut addrs = vec![];
                    let mut lines = vec![];
                    while pc < ops.len() {
                        match run_op(&mut ltctx, &hdr, ops, pc) {
                            RunResult::Ok(bytes) => {
                                pc += bytes;
                            }
                            RunResult::NewRow(bytes) => {
                                let finfo = ctx.file_info(ltctx.file_idx as usize);
                                let dirname = ctx.get_str(finfo.directory as usize);
                                let filename = ctx.get_str(finfo.filename as usize);
                                assert_eq!(dirname, "/rustc/17cbdfd07178349d0a3cecb8e7dde8f915666ced/library/alloc/src/vec");
                                assert_eq!(filename, "set_len_on_drop.rs");
                                addrs.push(ltctx.address);
                                lines.push(ltctx.file_line);
                                pc += bytes;
                            }
                            RunResult::Err => {
                                break;
                            }
                            RunResult::End => {
                                break;
                            }
                        }
                    }

                    assert_eq!(addrs.len(), 3);
                    assert_eq!(addrs[0], 0x29bda0);
                    assert_eq!(addrs[1], 0x29bda5);
                    assert_eq!(addrs[2], 0x29bdaf);
                    assert_eq!(lines[0], 25);
                    assert_eq!(lines[1], 26);
                    assert_eq!(lines[2], 27);
                    has_line_info = true;
                }
            }
        }
        assert!(has_line_info);

        let idx = find_address(&ctx, 0x29bda0);
        assert_eq!(idx, ctx.num_addresses() * 4 / 5);
    }
}

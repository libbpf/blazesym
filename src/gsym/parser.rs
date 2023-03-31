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
//! See <https://reviews.llvm.org/D53379>

use std::io::Error;
use std::io::ErrorKind;
use std::mem::align_of;

use crate::log::warn;
use crate::util::find_match_or_lower_bound;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Addr;

use super::linetab::LineTableHeader;
use super::types::AddressData;
use super::types::AddressInfo;
use super::types::FileInfo;
use super::types::Header;
use super::types::InfoTypeEndOfList;
use super::types::InfoTypeInlineInfo;
use super::types::InfoTypeLineTableInfo;
use super::types::GSYM_MAGIC;
use super::types::GSYM_VERSION;

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
    addr_data_off_tab: &'a [u32],
    file_tab: &'a [FileInfo],
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
    pub fn parse_header(data: &[u8]) -> Result<GsymContext, Error> {
        fn parse_header_impl(mut data: &[u8]) -> Option<Result<GsymContext, Error>> {
            let head = data;
            let magic = data.read_u32()?;
            if magic != GSYM_MAGIC {
                return Some(Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid magic number",
                )))
            }
            let version = data.read_u16()?;
            if version != GSYM_VERSION {
                return Some(Err(Error::new(
                    ErrorKind::InvalidData,
                    "unknown version number",
                )))
            }

            let addr_off_size = data.read_u8()?;
            let uuid_size = data.read_u8()?;
            let base_address = data.read_u64()?;
            let num_addrs = data.read_u32()?;
            let strtab_offset = data.read_u32()?;
            let strtab_size = data.read_u32()?;
            // SANITY: We know that the slice has 20 elements if read
            //         successful.
            let uuid = <[u8; 20]>::try_from(data.read_slice(20)?).unwrap();

            let addr_tab = data.read_slice(num_addrs as usize * usize::from(addr_off_size))?;
            let () = data.align(align_of::<u32>())?;
            let addr_data_off_tab = data.read_pod_slice_ref(num_addrs as usize)?;

            let file_num = data.read_u32()?;
            let () = data.align(align_of::<FileInfo>())?;
            let file_tab = data.read_pod_slice_ref(file_num as usize)?;

            let mut data = head.get(strtab_offset as usize..)?;
            let str_tab = data.read_slice(strtab_size as usize)?;

            let slf = GsymContext {
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
                raw_data: head,
            };
            Some(Ok(slf))
        }

        parse_header_impl(data).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "GSYM data does not contain sufficient bytes",
            )
        })?
    }

    #[inline]
    fn num_addresses(&self) -> usize {
        self.header.num_addrs as usize
    }

    /// Find the index of an entry in the address table potentially containing the
    /// given address.
    ///
    /// Callers should check the `AddressInfo` object at the returned index to see
    /// whether the symbol actually covers the provided address.
    pub fn find_address(&self, addr: Addr) -> Option<usize> {
        fn find_address_impl<T>(
            mut addr_tab: &[u8],
            num_addrs: usize,
            address: Addr,
        ) -> Option<usize>
        where
            T: Copy + Ord + TryFrom<Addr> + Pod + 'static,
        {
            let address = T::try_from(address).ok()?;
            let table = addr_tab.read_pod_slice_ref::<T>(num_addrs)?;
            find_match_or_lower_bound(table, address)
        }


        let relative_addr = addr.checked_sub(self.header.base_address as Addr)?;
        let num_addrs = self.header.num_addrs as usize;

        match self.header.addr_off_size {
            1 => find_address_impl::<u8>(self.addr_tab, num_addrs, relative_addr),
            2 => find_address_impl::<u16>(self.addr_tab, num_addrs, relative_addr),
            4 => find_address_impl::<u32>(self.addr_tab, num_addrs, relative_addr),
            8 => find_address_impl::<u64>(self.addr_tab, num_addrs, relative_addr),
            _ => None,
        }
    }

    /// Get the address of an entry in the Address Table.
    pub fn addr_at(&self, idx: usize) -> Option<Addr> {
        let addr_off_size = self.header.addr_off_size as usize;
        let mut data = self.addr_tab.get(idx * addr_off_size..)?;
        let address = match addr_off_size {
            1 => data.read_u8()?.into(),
            2 => data.read_u16()?.into(),
            4 => data.read_u32()? as Addr,
            8 => data.read_u64()? as Addr,
            _ => return None,
        };
        Some(self.header.base_address as Addr + address)
    }

    /// Get the AddressInfo of an address given by an index.
    pub fn addr_info(&self, idx: usize) -> Option<AddressInfo> {
        let offset = *self.addr_data_off_tab.get(idx)?;
        let mut data = self.raw_data.get(offset as usize..)?;
        let size = data.read_u32()?;
        let name = data.read_u32()?;
        let info = AddressInfo { size, name, data };

        Some(info)
    }

    /// Retrieve the [start, end] address range
    pub fn address_range(&self) -> Option<(Addr, Addr)> {
        let len = self.num_addresses();
        if len == 0 {
            return Some((0, 0))
        }

        let start = self.addr_at(0)?;
        let end = self.addr_at(len - 1)? + self.addr_info(len - 1)?.size as Addr;
        Some((start, end))
    }

    /// Get the string at the given offset from the String Table.
    #[inline]
    pub fn get_str(&self, offset: usize) -> Option<&str> {
        self.str_tab.get(offset..)?.read_cstr()?.to_str().ok()
    }

    #[inline]
    pub fn file_info(&self, idx: usize) -> Option<&FileInfo> {
        self.file_tab.get(idx)
    }
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
pub fn parse_address_data(mut data: &[u8]) -> Option<Vec<AddressData>> {
    let mut data_objs = vec![];

    while !data.is_empty() {
        let typ = data.read_u32()?;
        let length = data.read_u32()?;
        let d = data.read_slice(length as usize)?;
        data_objs.push(AddressData {
            typ,
            length,
            data: d,
        });

        #[allow(non_upper_case_globals)]
        match typ {
            InfoTypeEndOfList => break,
            InfoTypeLineTableInfo | InfoTypeInlineInfo => {}
            _ => {
                warn!("unknown info type");
            }
        }
    }

    Some(data_objs)
}

/// Parse AddressData of InfoTypeLineTableInfo.
///
/// An `AddressData` of `InfoTypeLineTableInfo` type is a table of line numbers
/// for a symbol. `AddressData` is the payload of `AddressInfo`. One
/// `AddressInfo` may have several `AddressData` entries in its payload. Each
/// `AddressData` entry stores a type of data relates to the symbol the
/// `AddressInfo` presents.
///
/// # Arguments
///
/// * `data` - is what [`AddressData::data`] is.
///
/// Returns the `LineTableHeader` and the size of the header of a
/// `AddressData` entry of `InfoTypeLineTableInfo` type in the payload
/// of an `Addressinfo`.
pub fn parse_line_table_header(data: &mut &[u8]) -> Option<LineTableHeader> {
    let (min_delta, _bytes) = data.read_i128_leb128()?;
    let (max_delta, _bytes) = data.read_i128_leb128()?;
    let (first_line, _bytes) = data.read_u128_leb128()?;

    let header = LineTableHeader {
        min_delta: min_delta as i64,
        max_delta: max_delta as i64,
        first_line: first_line as u32,
    };
    Some(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use std::path::Path;

    use test_log::test;


    #[test]
    fn test_parse_context() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        gsym_fo.read_to_end(&mut data).unwrap();
        let ctx = GsymContext::parse_header(&data).unwrap();

        let idx = ctx.find_address(0x0000000002000000).unwrap();
        let addrinfo = ctx.addr_info(idx).unwrap();
        assert_eq!(ctx.get_str(addrinfo.name as usize).unwrap(), "main");

        let idx = ctx.find_address(0x0000000002000100).unwrap();
        let addrinfo = ctx.addr_info(idx).unwrap();
        assert_eq!(ctx.get_str(addrinfo.name as usize).unwrap(), "factorial");
    }

    #[test]
    fn test_find_address() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        const TEST_SIZE: usize = 6;

        gsym_fo.read_to_end(&mut data).unwrap();

        let mut addr_tab = Vec::<u8>::new();
        addr_tab.resize(TEST_SIZE * 4, 0);

        let mut values: Vec<u32> = (0_u32..(TEST_SIZE as u32)).collect();

        let copy_to_addr_tab = |values: &[u32], addr_tab: &mut Vec<u8>| {
            addr_tab.clear();
            for v in values {
                let r = addr_tab.write(&v.to_ne_bytes());
                assert!(r.is_ok());
            }
        };
        // Generate all possible sequences that values are in strictly
        // ascending order and `< TEST_SIZE * 2`.
        let gen_values = |values: &mut [u32]| {
            let mut carry_out = TEST_SIZE as u32 * 2;
            for i in (0..values.len()).rev() {
                values[i] += 1;
                if values[i] >= carry_out {
                    carry_out -= 1;
                    continue
                }
                // Make all values at right side minimal and strictly
                // ascending.
                for j in (i + 1)..values.len() {
                    values[j] = values[j - 1] + 1;
                }
                break
            }
        };

        while values[0] <= TEST_SIZE as u32 {
            copy_to_addr_tab(&values, &mut addr_tab);

            for addr in 0..(TEST_SIZE * 2) {
                let addr_tab = addr_tab.clone();
                let mut ctx = GsymContext::parse_header(&data).unwrap();
                ctx.header.num_addrs = TEST_SIZE as u32;
                ctx.header.addr_off_size = 4;
                ctx.header.base_address = 0;
                ctx.addr_tab = addr_tab.as_slice();

                let idx = ctx.find_address(addr).unwrap_or(0);
                let addr_u32 = addr as u32;
                let idx1 = match values.binary_search(&addr_u32) {
                    Ok(idx) => idx,
                    Err(idx) => {
                        // When the searching value is falling in
                        // between two values, it will return the
                        // index of the later one. But we want the
                        // earlier one.
                        if idx > 0 {
                            idx - 1
                        } else {
                            0
                        }
                    }
                };
                assert_eq!(idx, idx1);
            }

            gen_values(&mut values);
        }
    }
}

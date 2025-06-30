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
//! Data. (`AddrInfo` actually)
//!
//! An `AddrInfo` comprises the size and name of a symbol.  The name
//! is an offset in the string table.  You will find a null terminated
//! C string at the give offset.  The size is the number of bytes of
//! the respective object; ex, a function or variable.
//!
//! See <https://reviews.llvm.org/D53379>

use std::ffi::OsStr;
use std::iter;
use std::mem::align_of;

use crate::util::bytes_to_os_str;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::IntoError as _;
use crate::Result;

use super::types::AddrData;
use super::types::AddrInfo;
use super::types::FileInfo;
use super::types::Header;
use super::types::GSYM_MAGIC;
use super::types::GSYM_VERSION;
use super::types::INFO_TYPE_END_OF_LIST;

/// Hold the major parts of a standalone GSYM file.
///
/// `GsymContext` provides functions to access major entities in GSYM.
/// `GsymContext` can find respective `AddrInfo` for an address.
pub(crate) struct GsymContext<'a> {
    header: Header,
    addr_tab: &'a [u8],
    addr_data_off_tab: &'a [u32],
    file_tab: &'a [FileInfo],
    str_tab: &'a [u8],
    raw_data: &'a [u8],
}

impl GsymContext<'_> {
    /// Parse the Header of a standalone GSYM file.
    ///
    /// # Arguments
    ///
    /// * `data` - is the content of a standalone GSYM.
    ///
    /// Returns a `GsymContext`, which includes the Header and other important
    /// tables.
    pub(crate) fn parse_header(data: &[u8]) -> Result<GsymContext<'_>> {
        fn parse_header_impl(mut data: &[u8]) -> Option<Result<GsymContext<'_>>> {
            let head = data;
            let magic = data.read_u32()?;
            if magic != GSYM_MAGIC {
                return Some(Err(Error::with_invalid_data("invalid magic number")))
            }
            let version = data.read_u16()?;
            if version != GSYM_VERSION {
                return Some(Err(Error::with_invalid_data("unknown version number")))
            }

            let addr_off_size = data.read_u8()?;
            let uuid_size = data.read_u8()?;
            let base_address = data.read_u64()?;
            let num_addrs = data.read_u32()?;
            let strtab_offset = data.read_u32()?;
            let strtab_size = data.read_u32()?;
            let uuid = data.read_array::<20>()?;

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
                    _magic: magic,
                    _version: version,
                    addr_off_size,
                    _uuid_size: uuid_size,
                    base_address,
                    num_addrs,
                    _strtab_offset: strtab_offset,
                    _strtab_size: strtab_size,
                    _uuid: uuid,
                },
                addr_tab,
                addr_data_off_tab,
                file_tab,
                str_tab,
                raw_data: head,
            };
            Some(Ok(slf))
        }

        parse_header_impl(data)
            .ok_or_invalid_data(|| "GSYM data does not contain sufficient bytes")?
    }

    /// Find the index of an entry in the address table potentially containing
    /// the given address.
    ///
    /// Callers should check the `AddrInfo` object at the returned index to see
    /// whether the symbol actually covers the provided address.
    pub(crate) fn find_addr(&self, addr: Addr) -> Option<usize> {
        fn find_addr_impl<T>(mut addr_tab: &[u8], num_addrs: usize, addr: Addr) -> Option<usize>
        where
            T: Copy + Ord + Into<Addr> + Pod + 'static,
        {
            let table = addr_tab.read_pod_slice_ref::<T>(num_addrs)?;
            find_match_or_lower_bound_by_key(table, addr, |x| Into::<Addr>::into(*x))
        }


        let relative_addr = addr.checked_sub(self.header.base_address)?;
        let num_addrs = self.header.num_addrs as usize;

        match self.header.addr_off_size {
            1 => find_addr_impl::<u8>(self.addr_tab, num_addrs, relative_addr),
            2 => find_addr_impl::<u16>(self.addr_tab, num_addrs, relative_addr),
            4 => find_addr_impl::<u32>(self.addr_tab, num_addrs, relative_addr),
            8 => find_addr_impl::<u64>(self.addr_tab, num_addrs, relative_addr),
            _ => None,
        }
    }

    /// Get the address of an entry in the Address Table.
    pub(crate) fn addr_at(&self, idx: usize) -> Option<Addr> {
        let addr_off_size = self.header.addr_off_size as usize;
        let mut data = self.addr_tab.get(idx.checked_mul(addr_off_size)?..)?;
        let addr = match addr_off_size {
            1 => data.read_u8()?.into(),
            2 => data.read_u16()?.into(),
            4 => data.read_u32()? as Addr,
            8 => data.read_u64()?,
            _ => return None,
        };
        (self.header.base_address).checked_add(addr)
    }

    /// Get the `AddrInfo` of an address given by an index.
    pub(crate) fn addr_info(&self, idx: usize) -> Option<AddrInfo<'_>> {
        let offset = *self.addr_data_off_tab.get(idx)?;
        let mut data = self.raw_data.get(offset as usize..)?;
        let size = data.read_u32()?;
        let name = data.read_u32()?;
        let info = AddrInfo { size, name, data };

        Some(info)
    }

    /// Get the string at the given offset from the String Table.
    #[inline]
    pub(crate) fn get_str(&self, offset: usize) -> Option<&OsStr> {
        let bytes = self.str_tab.get(offset..)?.read_cstr()?.to_bytes();
        bytes_to_os_str(bytes).ok()
    }

    #[inline]
    pub(crate) fn file_info(&self, idx: usize) -> Option<&FileInfo> {
        self.file_tab.get(idx)
    }
}


/// Parse [`AddrData`].
///
/// [`AddrData`] objects are items following [`AddrInfo`].
/// [`GsymContext::addr_info()`] returns the raw data of [`AddrData`] objects as
/// a slice at [`AddrInfo::data`].
///
/// # Arguments
///
/// * `data` - is the slice from `AddrInfo::data`.
pub(crate) fn parse_address_data(mut data: &[u8]) -> impl Iterator<Item = AddrData<'_>> {
    iter::from_fn(move || {
        let typ = data.read_u32()?;
        if typ == INFO_TYPE_END_OF_LIST {
            // We are done.
            return None
        }

        let len = data.read_u32()?;
        let d = data.read_slice(len as usize)?;

        // We don't validate `typ` here, because callers will have to dispatch
        // on it anyway.

        Some(AddrData { typ, data: d })
    })
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


    /// A fake address table that is guaranteed to be sufficiently aligned.
    #[repr(align(64))]
    struct AddrTab<const N: usize>([u8; N]);


    #[test]
    fn test_parse_context() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        gsym_fo.read_to_end(&mut data).unwrap();
        let ctx = GsymContext::parse_header(&data).unwrap();

        let idx = ctx.find_addr(0x2000000).unwrap();
        let addrinfo = ctx.addr_info(idx).unwrap();
        assert_eq!(ctx.get_str(addrinfo.name as usize).unwrap(), "main");

        let idx = ctx.find_addr(0x2000200).unwrap();
        let addrinfo = ctx.addr_info(idx).unwrap();
        assert_eq!(ctx.get_str(addrinfo.name as usize).unwrap(), "factorial");
    }

    #[test]
    fn test_find_addr() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        const TEST_SIZE: usize = 6;

        gsym_fo.read_to_end(&mut data).unwrap();

        let mut addr_tab = vec![0; TEST_SIZE * 4];
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

                let idx = ctx.find_addr(addr as Addr).unwrap_or(0);
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

    /// Check that we can correctly find an address table entry even if the
    /// address does not fit into `addr_off_size` bytes.
    #[test]
    fn overly_large_addr_finding() {
        let addr_tab = AddrTab([
            156, 96, 180, 96, 192, 96, 240, 96, 48, 97, 112, 97, 128, 97, 160, 97, 224, 100, 48,
            107, 32, 110, 128, 112, 208, 118, 80, 120, 160, 121, 144, 133, 48, 135, 160, 138, 224,
            140, 0, 244, 208, 245, 48, 247, 240, 248, 64, 250, 240, 251, 160, 252, 128, 255,
        ]);

        let context = GsymContext {
            header: Header {
                _magic: 1196644685,
                _version: 1,
                addr_off_size: 2,
                _uuid_size: 20,
                base_address: 0,
                num_addrs: 27,
                _strtab_offset: 224,
                _strtab_size: 697,
                _uuid: [
                    120, 151, 243, 48, 221, 52, 78, 164, 192, 149, 35, 25, 172, 82, 70, 123, 125,
                    239, 78, 50,
                ],
            },
            addr_tab: &addr_tab.0,
            addr_data_off_tab: &[
                924, 940, 956, 972, 988, 1004, 1020, 1036, 1052, 1068, 1084, 1100, 1116, 1132,
                1148, 1164, 1180, 1196, 1212, 1228, 1244, 1260, 1276, 1292, 1308, 1324, 1340,
            ],
            file_tab: &[],
            str_tab: &[],
            raw_data: &[],
        };

        // The address we are looking for (0x10635) does not fit into a `u16`.
        // Yet, it is valid (because the represented function's start address
        // fits into a `u16`) and should not cause a lookup failure.
        assert_eq!(context.find_addr(0x10635), Some(26));
    }
}

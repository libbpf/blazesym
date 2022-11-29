pub const GSYM_MAGIC: u32 = 0x4753594d;
pub const GSYM_VERSION: u16 = 1;

/// GSYM File Header
pub struct Header {
    pub magic: u32,
    pub version: u16,
    pub addr_off_size: u8,
    pub uuid_size: u8,
    pub base_address: u64,
    pub num_addrs: u32,
    pub strtab_offset: u32,
    pub strtab_size: u32,
    pub uuid: [u8; 20],
}

#[allow(dead_code)]
pub struct FileInfo {
    pub directory: u32,
    pub filename: u32,
}

pub struct AddressInfo<'a> {
    pub size: u32,
    pub name: u32,
    /// The raw data comprises a list of [`AddressData`].
    pub data: &'a [u8],
}

pub struct AddressData<'a> {
    /// The data type. Its value should be one of InfoType*.
    pub typ: u32,
    pub length: u32,
    pub data: &'a [u8],
}

#[derive(Clone)]
pub struct LineTableRow {
    pub address: u64,
    pub file_idx: u32,
    pub file_line: u32,
}

pub struct LineTableHeader {
    /// `min_data` & `max_delta` together is used to set the range and
    /// encoding of line delta in special operator.  Line delta is the
    /// number of lines that a line table row is different from the
    /// previous row.
    ///
    /// See `Special operators` in lintab.rs.
    pub min_delta: i64,
    pub max_delta: i64,
    pub first_line: u32,
}

#[allow(non_upper_case_globals)]
pub const InfoTypeEndOfList: u32 = 0;
#[allow(non_upper_case_globals)]
pub const InfoTypeLineTableInfo: u32 = 1;
#[allow(non_upper_case_globals)]
pub const InfoTypeInlineInfo: u32 = 2;

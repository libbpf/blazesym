use gimli::EndianSlice;

#[cfg(target_endian = "little")]
type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
type Endianess = gimli::BigEndian;

/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
pub(crate) type R<'dat> = EndianSlice<'dat, Endianess>;

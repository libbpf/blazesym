use gimli::EndianSlice;
use gimli::SectionId;

use crate::elf::ElfParser;
use crate::Result;


#[cfg(target_endian = "little")]
type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
type Endianess = gimli::BigEndian;

/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
pub(crate) type R<'dat> = EndianSlice<'dat, Endianess>;


fn load_section_impl<'elf>(parser: &'elf ElfParser, name: Option<&str>) -> Result<R<'elf>> {
    let data = if let Some(name) = name {
        let result = parser.find_section(name)?;
        match result {
            Some(idx) => parser.section_data(idx)?,
            // Make sure to return empty data if a section does not exist.
            None => &[],
        }
    } else {
        &[]
    };

    let reader = EndianSlice::new(data, Endianess::default());
    Ok(reader)
}

pub(super) fn load_section(parser: &ElfParser, id: SectionId) -> Result<R<'_>> {
    load_section_impl(parser, Some(id.name()))
}

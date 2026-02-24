use gimli::EndianSlice;
use gimli::RelocateReader;
use gimli::SectionId;

use crate::elf::relocations::RelocationMap;
use crate::elf::relocations::SectionRelocations;
use crate::elf::ElfParser;
use crate::Result;


#[cfg(target_endian = "little")]
pub(super) type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
pub(super) type Endianess = gimli::BigEndian;

/// The gimli reader type we currently use. Uses `RelocateReader` to
/// transparently apply ELF relocations during DWARF parsing (needed for
/// `ET_REL` / `.ko` files). For non-relocatable files, the relocation
/// map is empty and acts as a no-op.
pub(crate) type R<'dat> = RelocateReader<EndianSlice<'dat, Endianess>, &'dat RelocationMap>;


pub(super) fn load_section<'elf>(
    parser: &'elf ElfParser,
    id: SectionId,
    relocs: &'elf SectionRelocations,
) -> Result<R<'elf>> {
    let name = id.name();
    let (data, section_idx) = {
        let result = parser.find_section(name)?;
        match result {
            Some(idx) => (parser.section_data(idx)?, Some(idx)),
            None => (&[] as &[u8], None),
        }
    };

    let inner = EndianSlice::new(data, Endianess::default());
    let reloc_map = section_idx
        .map(|idx| relocs.get(idx))
        .unwrap_or(relocs.get(usize::MAX));
    let reader = RelocateReader::new(inner, reloc_map);
    Ok(reader)
}

pub(super) fn load_dwo_section<'elf>(
    parser: &'elf ElfParser,
    id: SectionId,
    relocs: &'elf SectionRelocations,
) -> Result<R<'elf>> {
    let name = id.dwo_name();
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

    let inner = EndianSlice::new(data, Endianess::default());
    // DWO files don't need relocations.
    let reloc_map = relocs.get(usize::MAX);
    let reader = RelocateReader::new(inner, reloc_map);
    Ok(reader)
}

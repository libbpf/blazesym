use crate::elf::relocations::RelocationMap;


impl gimli::read::Relocate for &RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        Ok(self.relocate(offset as u64, value as u64) as usize)
    }
}

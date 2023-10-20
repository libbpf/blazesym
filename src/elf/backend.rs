use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;

use super::ElfParser;


#[derive(Clone, Debug)]
pub(crate) enum ElfBackend {
    #[cfg(feature = "dwarf")]
    Dwarf(Rc<DwarfResolver>), // ELF w/ DWARF
    Elf(Rc<ElfParser>), // ELF w/o DWARF
}

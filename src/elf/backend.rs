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

impl ElfBackend {
    /// Retrieve the underlying [`ElfParser`].
    pub(crate) fn parser(&self) -> &ElfParser {
        match self {
            #[cfg(feature = "dwarf")]
            Self::Dwarf(resolver) => resolver.parser(),
            Self::Elf(parser) => parser,
        }
    }
}

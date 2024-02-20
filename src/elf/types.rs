use crate::util::Pod;
use crate::SymType;

const EI_NIDENT: usize = 16;

type Elf64_Addr = u64;
type Elf64_Half = u16;
type Elf64_Off = u64;
type Elf64_Word = u32;
type Elf64_Xword = u64;

pub(crate) const ET_EXEC: u16 = 2;
pub(crate) const ET_DYN: u16 = 3;

#[derive(Debug)]
#[repr(C)]
pub(crate) struct Elf64_Ehdr {
    pub e_ident: [u8; EI_NIDENT], /* ELF "magic number" */
    pub e_type: Elf64_Half,
    pub e_machine: Elf64_Half,
    pub e_version: Elf64_Word,
    pub e_entry: Elf64_Addr, /* Entry point virtual address */
    pub e_phoff: Elf64_Off,  /* Program header table file offset */
    pub e_shoff: Elf64_Off,  /* Section header table file offset */
    pub e_flags: Elf64_Word,
    pub e_ehsize: Elf64_Half,
    pub e_phentsize: Elf64_Half,
    pub e_phnum: Elf64_Half,
    pub e_shentsize: Elf64_Half,
    pub e_shnum: Elf64_Half,
    pub e_shstrndx: Elf64_Half,
}

// SAFETY: `Elf64_Ehdr` is valid for any bit pattern.
unsafe impl Pod for Elf64_Ehdr {}

pub(crate) const PT_LOAD: u32 = 1;

#[derive(Debug)]
#[repr(C)]
pub(crate) struct Elf64_Phdr {
    pub p_type: Elf64_Word,
    pub p_flags: Elf64_Word,
    pub p_offset: Elf64_Off,   /* Segment file offset */
    pub p_vaddr: Elf64_Addr,   /* Segment virtual address */
    pub p_paddr: Elf64_Addr,   /* Segment physical address */
    pub p_filesz: Elf64_Xword, /* Segment size in file */
    pub p_memsz: Elf64_Xword,  /* Segment size in memory */
    pub p_align: Elf64_Xword,  /* Segment alignment, file & memory */
}

// SAFETY: `Elf64_Phdr` is valid for any bit pattern.
unsafe impl Pod for Elf64_Phdr {}

pub(crate) const PF_X: Elf64_Word = 1;

pub(crate) const PN_XNUM: u16 = 0xffff;

#[derive(Debug)]
#[repr(C)]
pub(crate) struct Elf64_Shdr {
    pub sh_name: Elf64_Word,       /* Section name, index in string tbl */
    pub sh_type: Elf64_Word,       /* Type of section */
    pub sh_flags: Elf64_Xword,     /* Miscellaneous section attributes */
    pub sh_addr: Elf64_Addr,       /* Section virtual addr at execution */
    pub sh_offset: Elf64_Off,      /* Section file offset */
    pub sh_size: Elf64_Xword,      /* Size of section in bytes */
    pub sh_link: Elf64_Word,       /* Index of another section */
    pub sh_info: Elf64_Word,       /* Additional section information */
    pub sh_addralign: Elf64_Xword, /* Section alignment */
    pub sh_entsize: Elf64_Xword,   /* Entry size if section holds table */
}

// SAFETY: `Elf64_Shdr` is valid for any bit pattern.
unsafe impl Pod for Elf64_Shdr {}

pub(crate) const SHN_UNDEF: u16 = 0;
pub(crate) const SHN_LORESERVE: u16 = 0xff00;
pub(crate) const SHN_XINDEX: u16 = 0xffff;

pub(crate) const SHT_NOTE: Elf64_Word = 7;

pub(crate) const STT_OBJECT: u8 = 1;
pub(crate) const STT_FUNC: u8 = 2;
pub(crate) const STT_GNU_IFUNC: u8 = 10;

#[derive(Clone, Debug)]
#[repr(C)]
pub(crate) struct Elf64_Sym {
    pub st_name: Elf64_Word,  /* Symbol name, index in string tbl */
    pub st_info: u8,          /* Type and binding attributes */
    pub st_other: u8,         /* No defined meaning, 0 */
    pub st_shndx: Elf64_Half, /* Associated section index */
    pub st_value: Elf64_Addr, /* Value of the symbol */
    pub st_size: Elf64_Xword, /* Associated symbol size */
}

impl Elf64_Sym {
    /// Extract the symbols type, typically represented by a STT_* constant.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.st_info & 0xf
    }

    /// Check whether the symbol's type matches that represented by the
    /// given [`SymType`].
    #[inline]
    pub fn matches(&self, type_: SymType) -> bool {
        let elf_ty = self.type_();
        let is_func = elf_ty == STT_FUNC || elf_ty == STT_GNU_IFUNC;
        let is_var = elf_ty == STT_OBJECT;

        match type_ {
            SymType::Undefined => is_func || is_var,
            SymType::Function => is_func,
            SymType::Variable => is_var,
        }
    }
}

impl TryFrom<&Elf64_Sym> for SymType {
    type Error = ();

    fn try_from(other: &Elf64_Sym) -> Result<Self, Self::Error> {
        match other.type_() {
            STT_FUNC | STT_GNU_IFUNC => Ok(SymType::Function),
            STT_OBJECT => Ok(SymType::Variable),
            _ => Err(()),
        }
    }
}

// SAFETY: `Elf64_Sym` is valid for any bit pattern.
unsafe impl Pod for Elf64_Sym {}

pub(crate) const NT_GNU_BUILD_ID: Elf64_Word = 3;

#[derive(Debug)]
#[repr(C)]
pub(crate) struct Elf64_Nhdr {
    pub n_namesz: Elf64_Word,
    pub n_descsz: Elf64_Word,
    pub n_type: Elf64_Word,
}

// SAFETY: `Elf64_Nhdr` is valid for any bit pattern.
unsafe impl Pod for Elf64_Nhdr {}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let ehdr = Elf64_Ehdr {
            e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            e_type: 3,
            e_machine: 62,
            e_version: 1,
            e_entry: 4208,
            e_phoff: 64,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 64,
            e_phentsize: 56,
            e_phnum: 13,
            e_shentsize: 64,
            e_shnum: 0,
            e_shstrndx: 29,
        };
        assert_ne!(format!("{ehdr:?}"), "");

        let phdr = Elf64_Phdr {
            p_type: 0,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        };
        assert_ne!(format!("{phdr:?}"), "");

        let shdr = Elf64_Shdr {
            sh_name: 27,
            sh_type: 1,
            sh_flags: 2,
            sh_addr: 792,
            sh_offset: 792,
            sh_size: 28,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        };
        assert_ne!(format!("{shdr:?}"), "");

        let nhdr = Elf64_Nhdr {
            n_namesz: 0,
            n_descsz: 0,
            n_type: 0,
        };
        assert_ne!(format!("{nhdr:?}"), "");

        let sym = Elf64_Sym {
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
        };
        assert_ne!(format!("{sym:?}"), "");
    }
}

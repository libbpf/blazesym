const EI_NIDENT: usize = 16;

#[allow(non_camel_case_types)]
type Elf64_Addr = u64;
#[allow(non_camel_case_types)]
type Elf64_Half = u16;
#[allow(non_camel_case_types)]
#[allow(dead_code)]
type Elf64_SHalf = u16;
#[allow(non_camel_case_types)]
type Elf64_Off = u64;
#[allow(non_camel_case_types)]
#[allow(dead_code)]
type Elf64_Sword = i32;
#[allow(non_camel_case_types)]
type Elf64_Word = u32;
#[allow(non_camel_case_types)]
type Elf64_Xword = u64;
#[allow(non_camel_case_types)]
type Elf64_Sxword = i64;

#[allow(dead_code)]
pub const ET_NONE: u16 = 0;
#[allow(dead_code)]
pub const ET_REL: u16 = 1;
#[allow(dead_code)]
pub const ET_EXEC: u16 = 2;
#[allow(dead_code)]
pub const ET_DYN: u16 = 3;
#[allow(dead_code)]
pub const ET_CORE: u16 = 4;
#[allow(dead_code)]
pub const ET_LOPROC: u16 = 0xff00;
#[allow(dead_code)]
pub const ET_HIPROC: u16 = 0xffff;

#[repr(C)]
pub struct Elf64_Ehdr {
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

#[allow(dead_code)]
pub const PT_NULL: u32 = 0;
#[allow(dead_code)]
pub const PT_LOAD: u32 = 1;
#[allow(dead_code)]
pub const PT_DYNAMIC: u32 = 2;
#[allow(dead_code)]
pub const PT_INTERP: u32 = 3;
#[allow(dead_code)]
pub const PT_NOTE: u32 = 4;
#[allow(dead_code)]
pub const PT_SHLIB: u32 = 5;
#[allow(dead_code)]
pub const PT_PHDR: u32 = 6;
#[allow(dead_code)]
pub const PT_TLS: u32 = 7; /* Thread local storage segment */
#[allow(dead_code)]
pub const PT_LOOS: u32 = 0x60000000; /* OS-specific */
#[allow(dead_code)]
pub const PT_HIOS: u32 = 0x6fffffff; /* OS-specific */
#[allow(dead_code)]
pub const PT_LOPROC: u32 = 0x70000000;
#[allow(dead_code)]
pub const PT_HIPROC: u32 = 0x7fffffff;
#[allow(dead_code)]
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
#[allow(dead_code)]
pub const PT_GNU_PROPERTY: u32 = 0x6474e553;

#[allow(dead_code)]
pub const PT_GNU_STACK: u32 = PT_LOOS + 0x474e551;

#[repr(C)]
pub struct Elf64_Phdr {
    pub p_type: Elf64_Word,
    pub p_flags: Elf64_Word,
    pub p_offset: Elf64_Off,   /* Segment file offset */
    pub p_vaddr: Elf64_Addr,   /* Segment virtual address */
    pub p_paddr: Elf64_Addr,   /* Segment physical address */
    pub p_filesz: Elf64_Xword, /* Segment size in file */
    pub p_memsz: Elf64_Xword,  /* Segment size in memory */
    pub p_align: Elf64_Xword,  /* Segment alignment, file & memory */
}

#[allow(dead_code)]
pub const PF_X: Elf64_Word = 1;
#[allow(dead_code)]
pub const PF_W: Elf64_Word = 2;
#[allow(dead_code)]
pub const PF_R: Elf64_Word = 4;

#[repr(C)]
pub struct Elf64_Shdr {
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

pub const SHN_UNDEF: u16 = 0;

#[allow(dead_code)]
pub const STT_NOTYPE: u8 = 0;
#[allow(dead_code)]
pub const STT_OBJECT: u8 = 1;
#[allow(dead_code)]
pub const STT_FUNC: u8 = 2;

#[derive(Clone)]
#[repr(C)]
pub struct Elf64_Sym {
    pub st_name: Elf64_Word,  /* Symbol name, index in string tbl */
    pub st_info: u8,          /* Type and binding attributes */
    pub st_other: u8,         /* No defined meaning, 0 */
    pub st_shndx: Elf64_Half, /* Associated section index */
    pub st_value: Elf64_Addr, /* Value of the symbol */
    pub st_size: Elf64_Xword, /* Associated symbol size */
}

#[allow(dead_code)]
impl Elf64_Sym {
    pub fn get_type(&self) -> u8 {
        self.st_info & 0xf
    }

    pub fn is_undef(&self) -> bool {
        self.st_shndx == SHN_UNDEF
    }
}

#[allow(dead_code)]
#[repr(C)]
struct Elf64_Rel {
    pub r_offset: Elf64_Addr, /* Location at which to apply the action */
    pub r_info: Elf64_Xword,  /* index and type of relocation */
}

#[allow(dead_code)]
#[repr(C)]
struct Elf64_Rela {
    pub r_offset: Elf64_Addr,   /* Location at which to apply the action */
    pub r_info: Elf64_Xword,    /* index and type of relocation */
    pub r_addend: Elf64_Sxword, /* Constant addend used to compute value */
}

#[allow(dead_code)]
#[repr(C)]
union Elf64_Dyn_un {
    pub d_val: Elf64_Xword,
    pub d_ptr: Elf64_Addr,
}

#[allow(dead_code)]
#[repr(C)]
struct Elf64_Dyn {
    pub d_tag: Elf64_Sxword, /* entry tag value */
    pub d_un: Elf64_Dyn_un,
}

use std::borrow::Cow;

use crate::util::Either;
use crate::util::Pod;
use crate::SymType;

pub(crate) const EI_NIDENT: usize = 16;

type Elf64_Addr = u64;
type Elf64_Half = u16;
type Elf64_Off = u64;
type Elf64_Word = u32;
type Elf64_Xword = u64;

type Elf32_Addr = u32;
type Elf32_Half = u16;
type Elf32_Off = u32;
type Elf32_Word = u32;
type Elf32_Xword = u64;
type Elf32_Section = u16;


pub(crate) const ET_EXEC: u16 = 2;
pub(crate) const ET_DYN: u16 = 3;

pub(crate) const ELFCLASSNONE: u8 = 0;
pub(crate) const ELFCLASS32: u8 = 1;
pub(crate) const ELFCLASS64: u8 = 2;


#[derive(Debug)]
pub(crate) enum ElfN<'elf, T>
where
    T: Clone + Has32BitTy,
    T::Ty32Bit: Clone,
{
    B32(Cow<'elf, T::Ty32Bit>),
    B64(Cow<'elf, T>),
}

impl<T> ElfN<'_, T>
where
    T: Clone + Has32BitTy,
    T::Ty32Bit: Clone,
{
    pub fn is_32bit(&self) -> bool {
        matches!(self, Self::B32(..))
    }

    pub fn to_64bit(&self) -> T
    where
        T: Copy + for<'ty> From<&'ty T::Ty32Bit>,
    {
        match self {
            Self::B32(ty) => T::from(ty),
            Self::B64(ty) => **ty,
        }
    }
}


#[derive(Debug)]
pub(crate) enum ElfNSlice<'elf, T>
where
    T: Clone + Has32BitTy,
    T::Ty32Bit: Clone,
{
    B32(Cow<'elf, [T::Ty32Bit]>),
    B64(Cow<'elf, [T]>),
}

impl<T> ElfNSlice<'_, T>
where
    T: Clone + Has32BitTy,
    T::Ty32Bit: Clone,
{
    pub fn empty(tybit32: bool) -> Self {
        if tybit32 {
            Self::B32(Cow::Borrowed(&[]))
        } else {
            Self::B64(Cow::Borrowed(&[]))
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, idx: usize) -> Option<ElfN<'_, T>> {
        match self {
            Self::B32(slice) => Some(ElfN::B32(Cow::Borrowed(slice.get(idx)?))),
            Self::B64(slice) => Some(ElfN::B64(Cow::Borrowed(slice.get(idx)?))),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::B32(slice) => slice.len(),
            Self::B64(slice) => slice.len(),
        }
    }

    pub fn iter(&self, start_idx: usize) -> impl ExactSizeIterator<Item = ElfN<'_, T>> {
        match self {
            Self::B32(slice) => Either::A(
                slice[start_idx..]
                    .iter()
                    .map(|x| ElfN::B32(Cow::Borrowed(x))),
            ),
            Self::B64(slice) => Either::B(
                slice[start_idx..]
                    .iter()
                    .map(|x| ElfN::B64(Cow::Borrowed(x))),
            ),
        }
    }
}


pub(crate) trait Has32BitTy {
    type Ty32Bit;
}


#[derive(Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct Elf32_Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: Elf32_Half,
    pub e_machine: Elf32_Half,
    pub e_version: Elf32_Word,
    pub e_entry: Elf32_Addr,
    pub e_phoff: Elf32_Off,
    pub e_shoff: Elf32_Off,
    pub e_flags: Elf32_Word,
    pub e_ehsize: Elf32_Half,
    pub e_phentsize: Elf32_Half,
    pub e_phnum: Elf32_Half,
    pub e_shentsize: Elf32_Half,
    pub e_shnum: Elf32_Half,
    pub e_shstrndx: Elf32_Half,
}

// SAFETY: `Elf32_Ehdr` is valid for any bit pattern.
unsafe impl Pod for Elf32_Ehdr {}


#[derive(Clone, Debug, Default)]
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

impl Has32BitTy for Elf64_Ehdr {
    type Ty32Bit = Elf32_Ehdr;
}

pub(crate) type ElfN_Ehdr<'elf> = ElfN<'elf, Elf64_Ehdr>;

impl ElfN_Ehdr<'_> {
    #[inline]
    pub fn shnum(&self) -> Elf64_Half {
        match self {
            ElfN::B32(ehdr) => ehdr.e_shnum,
            ElfN::B64(ehdr) => ehdr.e_shnum,
        }
    }

    #[inline]
    pub fn phnum(&self) -> Elf64_Half {
        match self {
            ElfN::B32(ehdr) => ehdr.e_phnum,
            ElfN::B64(ehdr) => ehdr.e_phnum,
        }
    }

    #[inline]
    pub fn shoff(&self) -> Elf64_Off {
        match self {
            ElfN::B32(ehdr) => ehdr.e_shoff.into(),
            ElfN::B64(ehdr) => ehdr.e_shoff,
        }
    }

    #[inline]
    pub fn phoff(&self) -> Elf64_Off {
        match self {
            ElfN::B32(ehdr) => ehdr.e_phoff.into(),
            ElfN::B64(ehdr) => ehdr.e_phoff,
        }
    }

    #[inline]
    pub fn shstrndx(&self) -> Elf64_Half {
        match self {
            ElfN::B32(ehdr) => ehdr.e_shstrndx,
            ElfN::B64(ehdr) => ehdr.e_shstrndx,
        }
    }
}


pub(crate) const PT_LOAD: u32 = 1;


#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct Elf32_Phdr {
    pub p_type: Elf32_Word,   /* Segment type */
    pub p_offset: Elf32_Off,  /* Segment file offset */
    pub p_vaddr: Elf32_Addr,  /* Segment virtual address */
    pub p_paddr: Elf32_Addr,  /* Segment physical address */
    pub p_filesz: Elf32_Word, /* Segment size in file */
    pub p_memsz: Elf32_Word,  /* Segment size in memory */
    pub p_flags: Elf32_Word,  /* Segment flags */
    pub p_align: Elf32_Word,  /* Segment alignment */
}

// SAFETY: `Elf32_Phdr` is valid for any bit pattern.
unsafe impl Pod for Elf32_Phdr {}


#[derive(Copy, Clone, Debug, Default)]
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

impl From<&Elf32_Phdr> for Elf64_Phdr {
    fn from(other: &Elf32_Phdr) -> Self {
        Self {
            p_type: other.p_type,
            p_flags: other.p_flags,
            p_offset: other.p_offset.into(),
            p_vaddr: other.p_vaddr.into(),
            p_paddr: other.p_paddr.into(),
            p_filesz: other.p_filesz.into(),
            p_memsz: other.p_memsz.into(),
            p_align: other.p_align.into(),
        }
    }
}

impl Has32BitTy for Elf64_Phdr {
    type Ty32Bit = Elf32_Phdr;
}

pub(crate) type ElfN_Phdr<'elf> = ElfN<'elf, Elf64_Phdr>;
pub(crate) type ElfN_Phdrs<'elf> = ElfNSlice<'elf, Elf64_Phdr>;


pub(crate) const PF_X: Elf64_Word = 1;

pub(crate) const PN_XNUM: u16 = 0xffff;


#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct Elf32_Shdr {
    pub sh_name: Elf32_Word,
    pub sh_type: Elf32_Word,
    pub sh_flags: Elf32_Word,
    pub sh_addr: Elf32_Addr,
    pub sh_offset: Elf32_Off,
    pub sh_size: Elf32_Word,
    pub sh_link: Elf32_Word,
    pub sh_info: Elf32_Word,
    pub sh_addralign: Elf32_Word,
    pub sh_entsize: Elf32_Word,
}

// SAFETY: `Elf32_Shdr` is valid for any bit pattern.
unsafe impl Pod for Elf32_Shdr {}


#[derive(Copy, Clone, Debug, Default)]
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

impl From<&Elf32_Shdr> for Elf64_Shdr {
    fn from(other: &Elf32_Shdr) -> Self {
        Self {
            sh_name: other.sh_name,
            sh_type: other.sh_type,
            sh_flags: other.sh_flags.into(),
            sh_addr: other.sh_addr.into(),
            sh_offset: other.sh_offset.into(),
            sh_size: other.sh_size.into(),
            sh_link: other.sh_link,
            sh_info: other.sh_info,
            sh_addralign: other.sh_addralign.into(),
            sh_entsize: other.sh_entsize.into(),
        }
    }
}

impl Has32BitTy for Elf64_Shdr {
    type Ty32Bit = Elf32_Shdr;
}

pub(crate) type ElfN_Shdr<'elf> = ElfN<'elf, Elf64_Shdr>;
pub(crate) type ElfN_Shdrs<'elf> = ElfNSlice<'elf, Elf64_Shdr>;

impl ElfN_Shdr<'_> {
    #[inline]
    pub fn name(&self) -> Elf64_Word {
        match self {
            ElfN::B32(shdr) => shdr.sh_name,
            ElfN::B64(shdr) => shdr.sh_name,
        }
    }

    #[inline]
    pub fn type_(&self) -> Elf64_Word {
        match self {
            ElfN::B32(shdr) => shdr.sh_type,
            ElfN::B64(shdr) => shdr.sh_type,
        }
    }

    #[inline]
    pub fn flags(&self) -> Elf64_Xword {
        match self {
            ElfN::B32(shdr) => shdr.sh_flags.into(),
            ElfN::B64(shdr) => shdr.sh_flags,
        }
    }

    #[inline]
    pub fn addr(&self) -> Elf64_Addr {
        match self {
            ElfN::B32(shdr) => shdr.sh_addr.into(),
            ElfN::B64(shdr) => shdr.sh_addr,
        }
    }

    #[inline]
    pub fn offset(&self) -> Elf64_Off {
        match self {
            ElfN::B32(shdr) => shdr.sh_offset.into(),
            ElfN::B64(shdr) => shdr.sh_offset,
        }
    }

    #[inline]
    pub fn size(&self) -> Elf64_Xword {
        match self {
            ElfN::B32(shdr) => shdr.sh_size.into(),
            ElfN::B64(shdr) => shdr.sh_size,
        }
    }

    #[inline]
    pub fn link(&self) -> Elf64_Word {
        match self {
            ElfN::B32(shdr) => shdr.sh_link,
            ElfN::B64(shdr) => shdr.sh_link,
        }
    }
}


pub(crate) const SHF_COMPRESSED: u64 = 0x800;

pub(crate) const SHN_UNDEF: u16 = 0;
pub(crate) const SHN_LORESERVE: u16 = 0xff00;
pub(crate) const SHN_XINDEX: u16 = 0xffff;

pub(crate) const SHT_NOTE: Elf64_Word = 7;
pub(crate) const SHT_NOBITS: Elf64_Word = 8;

pub(crate) const STT_OBJECT: u8 = 1;
pub(crate) const STT_FUNC: u8 = 2;
pub(crate) const STT_GNU_IFUNC: u8 = 10;


fn elf_type_matches(elf_ty: u8, type_: SymType) -> bool {
    let is_func = elf_ty == STT_FUNC || elf_ty == STT_GNU_IFUNC;
    let is_var = elf_ty == STT_OBJECT;

    match type_ {
        SymType::Undefined => is_func || is_var,
        SymType::Function => is_func,
        SymType::Variable => is_var,
    }
}


#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct Elf32_Sym {
    pub st_name: Elf32_Word,
    pub st_value: Elf32_Addr,
    pub st_size: Elf32_Word,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: Elf32_Section,
}

impl Elf32_Sym {
    /// Extract the symbol's type, typically represented by a STT_*
    /// constant.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.st_info & 0xf
    }

    /// Check whether the symbol's type matches that represented by the
    /// given [`SymType`].
    #[inline]
    pub fn matches(&self, type_: SymType) -> bool {
        elf_type_matches(self.type_(), type_)
    }
}

// SAFETY: `Elf32_Sym` is valid for any bit pattern.
unsafe impl Pod for Elf32_Sym {}


#[derive(Clone, Copy, Debug, Default)]
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
    /// Extract the symbol's type, typically represented by a STT_*
    /// constant.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.st_info & 0xf
    }

    /// Check whether the symbol's type matches that represented by the
    /// given [`SymType`].
    #[inline]
    pub fn matches(&self, type_: SymType) -> bool {
        elf_type_matches(self.type_(), type_)
    }
}


impl SymType {
    fn try_from_elf_type(elf_type: u8) -> Result<Self, ()> {
        match elf_type {
            STT_FUNC | STT_GNU_IFUNC => Ok(SymType::Function),
            STT_OBJECT => Ok(SymType::Variable),
            _ => Err(()),
        }
    }
}

impl TryFrom<&Elf64_Sym> for SymType {
    type Error = ();

    fn try_from(other: &Elf64_Sym) -> Result<Self, Self::Error> {
        SymType::try_from_elf_type(other.type_())
    }
}

impl TryFrom<&ElfN<'_, Elf64_Sym>> for SymType {
    type Error = ();

    fn try_from(other: &ElfN<'_, Elf64_Sym>) -> Result<Self, Self::Error> {
        SymType::try_from_elf_type(other.type_())
    }
}


// SAFETY: `Elf64_Sym` is valid for any bit pattern.
unsafe impl Pod for Elf64_Sym {}

impl From<&Elf32_Sym> for Elf64_Sym {
    fn from(other: &Elf32_Sym) -> Self {
        Self {
            st_name: other.st_name,
            st_info: other.st_info,
            st_other: other.st_other,
            st_shndx: other.st_shndx,
            st_value: other.st_value.into(),
            st_size: other.st_size.into(),
        }
    }
}

impl Has32BitTy for Elf64_Sym {
    type Ty32Bit = Elf32_Sym;
}

pub(crate) type ElfN_Sym<'elf> = ElfN<'elf, Elf64_Sym>;
pub(crate) type ElfN_Syms<'elf> = ElfNSlice<'elf, Elf64_Sym>;

impl ElfN_Sym<'_> {
    #[inline]
    pub fn name(&self) -> Elf64_Word {
        match self {
            ElfN::B32(sym) => sym.st_name,
            ElfN::B64(sym) => sym.st_name,
        }
    }

    #[inline]
    pub fn value(&self) -> Elf64_Addr {
        match self {
            ElfN::B32(sym) => sym.st_value.into(),
            ElfN::B64(sym) => sym.st_value,
        }
    }

    #[inline]
    pub fn size(&self) -> Elf64_Xword {
        match self {
            ElfN::B32(sym) => sym.st_size.into(),
            ElfN::B64(sym) => sym.st_size,
        }
    }

    #[inline]
    pub fn type_(&self) -> u8 {
        match self {
            ElfN::B32(sym) => sym.type_(),
            ElfN::B64(sym) => sym.type_(),
        }
    }

    #[inline]
    pub fn shndx(&self) -> Elf64_Half {
        match self {
            ElfN::B32(sym) => sym.st_shndx,
            ElfN::B64(sym) => sym.st_shndx,
        }
    }

    #[inline]
    pub fn matches(&self, type_: SymType) -> bool {
        elf_type_matches(self.type_(), type_)
    }
}


pub(crate) const NT_GNU_BUILD_ID: Elf64_Word = 3;


#[derive(Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct Elf32_Nhdr {
    pub n_namesz: Elf32_Word, /* Length of the note's name. */
    pub n_descsz: Elf32_Word, /* Length of the note's descriptor. */
    pub n_type: Elf32_Word,   /* Type of the note. */
}

// SAFETY: `Elf32_Nhdr` is valid for any bit pattern.
unsafe impl Pod for Elf32_Nhdr {}


#[derive(Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct Elf64_Nhdr {
    pub n_namesz: Elf64_Word,
    pub n_descsz: Elf64_Word,
    pub n_type: Elf64_Word,
}

// SAFETY: `Elf64_Nhdr` is valid for any bit pattern.
unsafe impl Pod for Elf64_Nhdr {}

impl Has32BitTy for Elf64_Nhdr {
    type Ty32Bit = Elf32_Nhdr;
}


#[derive(Clone, Debug)]
#[repr(C)]
pub(crate) struct Elf32_Chdr {
    pub ch_type: Elf32_Word,      /* Compression format. */
    pub ch_size: Elf32_Word,      /* Uncompressed data size. */
    pub ch_addralign: Elf32_Word, /* Uncompressed data alignment. */
}

// SAFETY: `Elf32_Chdr` is valid for any bit pattern.
unsafe impl Pod for Elf32_Chdr {}


#[derive(Clone, Debug)]
#[repr(C)]
pub(crate) struct Elf64_Chdr {
    /// Compression format.
    ///
    /// See `ELFCOMPRESS_*` constants for supported values.
    pub ch_type: Elf64_Word,
    pub ch_reserved: Elf64_Word,
    /// Uncompressed data size.
    pub ch_size: Elf64_Xword,
    /// Uncompressed data alignment.
    pub ch_addralign: Elf64_Xword,
}

// SAFETY: `Elf64_Chdr` is valid for any bit pattern.
unsafe impl Pod for Elf64_Chdr {}

impl Has32BitTy for Elf64_Chdr {
    type Ty32Bit = Elf32_Chdr;
}


/// zlib/deflate algorithm.
pub(crate) const ELFCOMPRESS_ZLIB: u32 = 1;
/// zstd algorithm.
pub(crate) const ELFCOMPRESS_ZSTD: u32 = 2;


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let ehdr = Elf64_Ehdr::default();
        assert_ne!(format!("{ehdr:?}"), "");

        let phdr = Elf64_Phdr::default();
        assert_ne!(format!("{phdr:?}"), "");

        let shdr = Elf64_Shdr::default();
        assert_ne!(format!("{shdr:?}"), "");

        let nhdr = Elf64_Nhdr::default();
        assert_ne!(format!("{nhdr:?}"), "");

        let sym = Elf64_Sym::default();
        assert_ne!(format!("{sym:?}"), "");
    }

    /// Exercise some trivial type conversion functions.
    #[test]
    fn conversions() {
        let shdr = Elf32_Shdr::default();
        let _shdr64 = Elf64_Shdr::from(&shdr);

        let phdr = Elf32_Phdr::default();
        let _phdr64 = Elf64_Phdr::from(&phdr);

        let sym = Elf32_Sym::default();
        let _sym64 = Elf64_Sym::from(&sym);
    }

    /// Exercise some accessor functions.
    #[test]
    fn accessors() {
        let ehdr32 = Elf32_Ehdr::default();
        let ehdr = ElfN_Ehdr::B32(Cow::Borrowed(&ehdr32));
        let _val = ehdr.phoff();

        let shdr32 = Elf32_Shdr::default();
        let shdr = ElfN_Shdr::B32(Cow::Borrowed(&shdr32));
        let _val = shdr.addr();
        let _val = shdr.link();

        let sym32 = Elf32_Sym::default();
        let sym = ElfN_Sym::B32(Cow::Borrowed(&sym32));
        let _val = sym.value();
        let _val = sym.size();
        let _val = sym.type_();
        let _val = sym.shndx();
    }
}

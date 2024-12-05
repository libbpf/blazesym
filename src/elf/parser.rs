use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem;
use std::ops::ControlFlow;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;

use crate::insert_map::InsertMap;
use crate::inspect::FindAddrOpts;
use crate::inspect::ForEachFn;
use crate::inspect::SymInfo;
use crate::mmap::Mmap;
use crate::once::OnceCell;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;
use crate::SymType;

use super::types::Elf32_Ehdr;
use super::types::Elf32_Shdr;
use super::types::Elf64_Chdr;
use super::types::Elf64_Ehdr;
use super::types::Elf64_Phdr;
use super::types::Elf64_Shdr;
use super::types::Elf64_Sym;
use super::types::ElfN_Ehdr;
use super::types::ElfN_Shdr;
use super::types::ElfN_Shdrs;
use super::types::EI_NIDENT;
use super::types::ELFCLASS32;
use super::types::ELFCLASS64;
use super::types::ELFCOMPRESS_ZLIB;
use super::types::ELFCOMPRESS_ZSTD;
use super::types::PN_XNUM;
use super::types::PT_LOAD;
use super::types::SHF_COMPRESSED;
use super::types::SHN_LORESERVE;
use super::types::SHN_UNDEF;
use super::types::SHN_XINDEX;
use super::types::SHT_NOBITS;


fn symbol_name<'mmap>(strtab: &'mmap [u8], sym: &Elf64_Sym) -> Result<&'mmap str> {
    let name = strtab
        .get(sym.st_name as usize..)
        .ok_or_invalid_input(|| "string table index out of bounds")?
        .read_cstr()
        .ok_or_invalid_input(|| "no valid string found in string table")?
        .to_str()
        .map_err(Error::with_invalid_data)
        .context("invalid symbol name")?;

    Ok(name)
}

fn find_sym<'mmap>(
    symtab: &[&Elf64_Sym],
    strtab: &'mmap [u8],
    addr: Addr,
    type_: SymType,
) -> Result<Option<ResolvedSym<'mmap>>> {
    match find_match_or_lower_bound_by_key(symtab, addr, |sym| sym.st_value as Addr) {
        None => Ok(None),
        Some(idx) => {
            for sym in symtab[idx..].iter() {
                if sym.st_value as Addr > addr {
                    // Once we are seeing start addresses past the provided
                    // address, we can no longer be dealing with a match and
                    // stop the search.
                    break
                }

                // In ELF, a symbol size of 0 indicates "no size or an unknown
                // size" (see elf(5)). We take our chances and report these on a
                // best-effort basis.
                if sym.matches(type_)
                    && sym.st_shndx != SHN_UNDEF
                    && (sym.st_size == 0 || addr < sym.st_value + sym.st_size)
                {
                    let sym = ResolvedSym {
                        name: symbol_name(strtab, sym)?,
                        addr: sym.st_value as Addr,
                        size: if sym.st_size == 0 {
                            None
                        } else {
                            Some(usize::try_from(sym.st_size).unwrap_or(usize::MAX))
                        },
                        // ELF does not carry any source code language
                        // information.
                        lang: SrcLang::Unknown,
                        // ELF doesn't carry source code location
                        // information.
                        code_info: None,
                        inlined: Box::new([]),
                    };
                    return Ok(Some(sym))
                }
            }
            Ok(None)
        }
    }
}


#[cfg(feature = "zlib")]
fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use miniz_oxide::inflate::decompress_to_vec_zlib;

    match decompress_to_vec_zlib(data) {
        Ok(data) => Ok(data),
        Err(err) => Err(Error::with_invalid_data(format!(
            "zlib decompression failed: {err}"
        ))),
    }
}

#[cfg(not(feature = "zlib"))]
fn decompress_zlib(_data: &[u8]) -> Result<Vec<u8>> {
    Err(Error::with_unsupported(
        "ELF section is zlib compressed but zlib compression support is not enabled",
    ))
}

#[cfg(feature = "zstd")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    use zstd::stream::decode_all;
    decode_all(data).context("zstd decompression failed")
}

#[cfg(not(feature = "zstd"))]
fn decompress_zstd(_data: &[u8]) -> Result<Vec<u8>> {
    Err(Error::with_unsupported(
        "ELF section is zstd compressed but zstd compression support is not enabled",
    ))
}


#[derive(Debug)]
struct EhdrExt<'mmap> {
    /// The ELF header.
    ehdr: ElfN_Ehdr<'mmap>,
    /// Override of `ehdr.e_shnum`, handling of which is special-cased by
    /// the ELF standard.
    shnum: usize,
    /// Override of `ehdr.e_phnum`, handling of which is special-cased by
    /// the ELF standard.
    phnum: usize,
}

impl EhdrExt<'_> {
    fn is_32bit(&self) -> bool {
        self.ehdr.is_32bit()
    }
}


#[derive(Debug)]
struct SymbolTableCache<'mmap> {
    /// The cached symbols (in address order).
    syms: Box<[&'mmap Elf64_Sym]>,
    /// The string table.
    strs: &'mmap [u8],
    /// The cached name to symbol index table (in dictionary order).
    str2sym: OnceCell<Box<[(&'mmap str, usize)]>>,
}

impl<'mmap> SymbolTableCache<'mmap> {
    fn new(syms: Box<[&'mmap Elf64_Sym]>, strs: &'mmap [u8]) -> Self {
        Self {
            syms,
            strs,
            str2sym: OnceCell::new(),
        }
    }

    fn create_str2sym<F>(&self, mut filter: F) -> Result<Vec<(&'mmap str, usize)>>
    where
        F: FnMut(&Elf64_Sym) -> bool,
    {
        let mut str2sym = self
            .syms
            .iter()
            .filter(|sym| filter(sym))
            .enumerate()
            .map(|(i, sym)| {
                let name = self
                    .strs
                    .get(sym.st_name as usize..)
                    .ok_or_invalid_input(|| "ELF string table index out of bounds")?
                    .read_cstr()
                    .ok_or_invalid_input(|| "no valid string found in ELF string table")?
                    .to_str()
                    .map_err(Error::with_invalid_data)
                    .context("invalid ELF symbol name")?;
                Ok((name, i))
            })
            .collect::<Result<Vec<_>>>()?;

        let () = str2sym.sort_by_key(|&(name, _i)| name);
        Ok(str2sym)
    }

    fn ensure_str2sym<F>(&self, filter: F) -> Result<&[(&'mmap str, usize)]>
    where
        F: FnMut(&Elf64_Sym) -> bool,
    {
        let str2sym = self
            .str2sym
            .get_or_try_init(|| {
                let str2sym = self.create_str2sym(filter)?;
                let str2sym = str2sym.into_boxed_slice();
                Result::<_, Error>::Ok(str2sym)
            })?
            .deref();

        Ok(str2sym)
    }
}


struct Cache<'mmap> {
    /// A slice of the raw ELF data that we are about to parse.
    elf_data: &'mmap [u8],
    /// The cached ELF header.
    ehdr: OnceCell<EhdrExt<'mmap>>,
    /// The cached ELF section headers.
    shdrs: OnceCell<ElfN_Shdrs<'mmap>>,
    shstrtab: OnceCell<&'mmap [u8]>,
    /// The cached ELF program headers.
    phdrs: OnceCell<&'mmap [Elf64_Phdr]>,
    /// The cached symbol table.
    symtab: OnceCell<SymbolTableCache<'mmap>>,
    /// The cached dynamic symbol table.
    dynsym: OnceCell<SymbolTableCache<'mmap>>,
}

impl<'mmap> Cache<'mmap> {
    /// Create a new `Cache` using the provided raw ELF object data.
    fn new(elf_data: &'mmap [u8]) -> Self {
        Self {
            elf_data,
            ehdr: OnceCell::new(),
            shdrs: OnceCell::new(),
            shstrtab: OnceCell::new(),
            phdrs: OnceCell::new(),
            symtab: OnceCell::new(),
            dynsym: OnceCell::new(),
        }
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`, along with its section header.
    fn section_data_raw(&self, idx: usize) -> Result<(ElfN_Shdr<'mmap>, &'mmap [u8])> {
        let shdrs = self.ensure_shdrs()?;
        let shdr = shdrs
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF section index ({idx}) out of bounds"))?;

        if shdr.type_() != SHT_NOBITS {
            let data = self
                .elf_data
                .get(shdr.offset() as usize..)
                .ok_or_invalid_data(|| "failed to read ELF section data: invalid offset")?
                .read_slice(shdr.size() as usize)
                .ok_or_invalid_data(|| "failed to read ELF section data: invalid size")?;
            Ok((shdr, data))
        } else {
            Ok((shdr, &[]))
        }
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`.
    fn section_data(&self, idx: usize) -> Result<&'mmap [u8]> {
        self.section_data_raw(idx).map(|(_section, data)| data)
    }

    /// Read the very first section header.
    ///
    /// ELF contains a couple of clauses that special case data ranges
    /// of certain member variables to reference data from this header,
    /// which otherwise is zeroed out.
    #[inline]
    fn read_first_shdr(&self, ehdr: ElfN_Ehdr<'_>) -> Result<ElfN_Shdr<'mmap>> {
        let mut data = self
            .elf_data
            .get(ehdr.shoff() as usize..)
            .ok_or_invalid_data(|| "ELF e_shoff is invalid")?;

        let shdr = if ehdr.is_32bit() {
            data.read_pod_ref::<Elf32_Shdr>().map(ElfN_Shdr::B32)
        } else {
            data.read_pod_ref::<Elf64_Shdr>().map(ElfN_Shdr::B64)
        }
        .ok_or_invalid_data(|| "failed to read ELF section header")?;

        Ok(shdr)
    }

    fn parse_ehdr(&self) -> Result<EhdrExt<'mmap>> {
        let mut elf_data = self.elf_data;
        let e_ident = elf_data
            .peek_array::<EI_NIDENT>()
            .ok_or_invalid_data(|| "failed to read ELF e_ident information")?;
        if !(e_ident[0] == 0x7f && e_ident[1] == b'E' && e_ident[2] == b'L' && e_ident[3] == b'F') {
            return Err(Error::with_invalid_data(format!(
                "encountered unexpected e_ident: {:x?}",
                &e_ident[0..4]
            )))
        }

        let class = e_ident[4];
        if ![ELFCLASS32, ELFCLASS64].contains(&class) {
            return Err(Error::with_unsupported(format!(
                "ELF class ({class}) is not currently supported"
            )))
        }

        let bit32 = class == ELFCLASS32;
        let (ehdr, e_shnum, e_phnum) = if bit32 {
            let ehdr = elf_data
                .read_pod_ref::<Elf32_Ehdr>()
                .ok_or_invalid_data(|| "failed to read ELF header")?;
            (ElfN_Ehdr::B32(ehdr), ehdr.e_shnum, ehdr.e_phnum)
        } else {
            let ehdr = elf_data
                .read_pod_ref::<Elf64_Ehdr>()
                .ok_or_invalid_data(|| "failed to read ELF header")?;
            (ElfN_Ehdr::B64(ehdr), ehdr.e_shnum, ehdr.e_phnum)
        };

        // "If the number of entries in the section header table is larger than
        // or equal to SHN_LORESERVE, e_shnum holds the value zero and the real
        // number of entries in the section header table is held in the sh_size
        // member of the initial entry in section header table."
        let shnum = if e_shnum == 0 {
            let shdr = self.read_first_shdr(ehdr)?.to_64bit();
            usize::try_from(shdr.sh_size).ok().ok_or_invalid_data(|| {
                format!(
                    "ELF file contains unsupported number of sections ({})",
                    shdr.sh_size
                )
            })?
        } else {
            e_shnum.into()
        };

        // "If the number of entries in the program header table is
        // larger than or equal to PN_XNUM (0xffff), this member holds
        // PN_XNUM (0xffff) and the real number of entries in the
        // program header table is held in the sh_info member of the
        // initial entry in section header table."
        let phnum = if e_phnum == PN_XNUM {
            let shdr = self.read_first_shdr(ehdr)?.to_64bit();
            usize::try_from(shdr.sh_info).ok().ok_or_invalid_data(|| {
                format!(
                    "ELF file contains unsupported number of program headers ({})",
                    shdr.sh_info
                )
            })?
        } else {
            e_phnum.into()
        };

        let ehdr = EhdrExt { ehdr, shnum, phnum };
        Ok(ehdr)
    }

    fn ensure_ehdr(&self) -> Result<&EhdrExt<'mmap>> {
        self.ehdr.get_or_try_init(|| self.parse_ehdr())
    }

    fn parse_shdrs(&self) -> Result<ElfN_Shdrs<'mmap>> {
        let ehdr = self.ensure_ehdr()?;

        let mut data = self
            .elf_data
            .get(ehdr.ehdr.shoff() as usize..)
            .ok_or_invalid_data(|| "ELF e_shoff is invalid")?;

        let shdrs = if ehdr.is_32bit() {
            data.read_pod_slice_ref::<Elf32_Shdr>(ehdr.shnum)
                .map(ElfN_Shdrs::B32)
        } else {
            data.read_pod_slice_ref::<Elf64_Shdr>(ehdr.shnum)
                .map(ElfN_Shdrs::B64)
        }
        .ok_or_invalid_data(|| "failed to read ELF section headers")?;

        Ok(shdrs)
    }

    fn ensure_shdrs(&self) -> Result<ElfN_Shdrs<'mmap>> {
        self.shdrs.get_or_try_init(|| self.parse_shdrs()).copied()
    }

    fn parse_phdrs(&self) -> Result<&'mmap [Elf64_Phdr]> {
        let ehdr = self.ensure_ehdr()?;
        let phdrs = self
            .elf_data
            .get(ehdr.ehdr.phoff() as usize..)
            .ok_or_invalid_data(|| "Elf64_Ehdr::e_phoff is invalid")?
            .read_pod_slice_ref::<Elf64_Phdr>(ehdr.phnum)
            .ok_or_invalid_data(|| "failed to read Elf64_Phdr")?;
        Ok(phdrs)
    }

    fn ensure_phdrs(&self) -> Result<&'mmap [Elf64_Phdr]> {
        self.phdrs.get_or_try_init(|| self.parse_phdrs()).copied()
    }

    fn shstrndx(&self, ehdr: ElfN_Ehdr<'_>) -> Result<usize> {
        let e_shstrndx = ehdr.shstrndx();
        // "If the index of section name string table section is larger
        // than or equal to SHN_LORESERVE (0xff00), this member holds
        // SHN_XINDEX (0xffff) and  the real index of the section name
        // string table section is held in the sh_link member of the
        // initial entry in section header table."
        let shstrndx = if e_shstrndx == SHN_XINDEX {
            self.read_first_shdr(ehdr)?.link()
        } else {
            u32::from(e_shstrndx)
        };

        let shstrndx = usize::try_from(shstrndx).ok().ok_or_invalid_data(|| {
            format!("ELF file contains unsupported section name string table index ({shstrndx})")
        })?;
        Ok(shstrndx)
    }

    fn parse_shstrtab(&self) -> Result<&'mmap [u8]> {
        let ehdr = self.ensure_ehdr()?;
        let shstrndx = self.shstrndx(ehdr.ehdr)?;
        let shstrtab = self.section_data(shstrndx)?;
        Ok(shstrtab)
    }

    fn ensure_shstrtab(&self) -> Result<&'mmap [u8]> {
        self.shstrtab
            .get_or_try_init(|| self.parse_shstrtab())
            .copied()
    }

    /// Get the name of the section at a given index.
    fn section_name(&self, idx: usize) -> Result<&'mmap str> {
        let shdrs = self.ensure_shdrs()?;
        let shstrtab = self.ensure_shstrtab()?;

        let shdr = shdrs
            .get(idx)
            .ok_or_invalid_input(|| "ELF section index out of bounds")?;

        let name = shstrtab
            .get(shdr.name() as usize..)
            .ok_or_invalid_input(|| "ELF string table index out of bounds")?
            .read_cstr()
            .ok_or_invalid_input(|| "no valid string found in ELF string table")?
            .to_str()
            .map_err(Error::with_invalid_data)
            .context("invalid section name")?;
        Ok(name)
    }

    #[cfg(test)]
    fn symbol(&self, idx: usize) -> Result<&'mmap Elf64_Sym> {
        let symtab = self.ensure_symtab()?;
        let symbol = symtab
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF symbol index ({idx}) out of bounds"))?;

        Ok(symbol)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let ehdr = self.ensure_ehdr()?;
        for i in 1..ehdr.shnum {
            if self.section_name(i)? == name {
                return Ok(Some(i))
            }
        }
        Ok(None)
    }

    fn parse_syms(&self, section: &str) -> Result<Box<[&'mmap Elf64_Sym]>> {
        let idx = if let Some(idx) = self.find_section(section)? {
            idx
        } else {
            // The symbol table does not exists. Fake an empty one.
            return Ok(Box::new([]))
        };
        let mut syms = self.section_data(idx)?;

        if syms.len() % mem::size_of::<Elf64_Sym>() != 0 {
            return Err(Error::with_invalid_data(
                "size of ELF symbol table section is invalid",
            ))
        }

        let count = syms.len() / mem::size_of::<Elf64_Sym>();
        // Short-circuit if there are no symbols. The data may not actually be
        // properly aligned in this case either, so don't attempt to even read.
        if count == 0 {
            return Ok(Box::new([]))
        }
        let mut syms = syms
            .read_pod_slice_ref::<Elf64_Sym>(count)
            .ok_or_invalid_data(|| format!("failed to read ELF {section} symbol table contents"))?
            .iter()
            // Filter out any symbols that we do not support.
            .filter(|sym| sym.matches(SymType::Undefined))
            .collect::<Box<[&Elf64_Sym]>>();
        // Order symbols by address and those with equal address descending by
        // size.
        let () = syms.sort_by(|sym1, sym2| {
            sym1.st_value
                .cmp(&sym2.st_value)
                .then_with(|| sym1.st_size.cmp(&sym2.st_size).reverse())
        });

        Ok(syms)
    }

    fn ensure_symtab_cache(&self) -> Result<&SymbolTableCache<'mmap>> {
        self.symtab.get_or_try_init(|| {
            let syms = self.parse_syms(".symtab")?;
            let strtab = self.parse_strs(".strtab")?;
            let cache = SymbolTableCache::new(syms, strtab);
            Ok(cache)
        })
    }

    fn ensure_dynsym_cache(&self) -> Result<&SymbolTableCache<'mmap>> {
        self.dynsym.get_or_try_init(|| {
            // TODO: We really should check the `.dynamic` section for
            //       information on what symbol and string tables to
            //       use instead of hard coding names here.
            let syms = self.parse_syms(".dynsym")?;
            let dynstr = self.parse_strs(".dynstr")?;
            let cache = SymbolTableCache::new(syms, dynstr);
            Ok(cache)
        })
    }

    fn ensure_symtab(&self) -> Result<&[&'mmap Elf64_Sym]> {
        let symtab = self.ensure_symtab_cache()?;
        Ok(&symtab.syms)
    }

    fn ensure_dynsym(&self) -> Result<&[&'mmap Elf64_Sym]> {
        let dynsym = self.ensure_dynsym_cache()?;
        Ok(&dynsym.syms)
    }

    fn parse_strs(&self, section: &str) -> Result<&'mmap [u8]> {
        let strs = if let Some(idx) = self.find_section(section)? {
            self.section_data(idx)?
        } else {
            &[]
        };
        Ok(strs)
    }

    fn ensure_str2symtab(&self) -> Result<&[(&'mmap str, usize)]> {
        let symtab = self.ensure_symtab_cache()?;
        let str2sym = symtab.ensure_str2sym(|_sym| true)?;
        Ok(str2sym)
    }

    fn ensure_str2dynsym(&self) -> Result<&[(&'mmap str, usize)]> {
        let symtab = self.ensure_symtab_cache()?;
        let dynsym = self.ensure_dynsym_cache()?;
        let str2sym = dynsym.ensure_str2sym(|sym| {
            // We filter out all the symbols that already exist in symtab,
            // to prevent any duplicates from showing up.
            let result = find_sym(
                &symtab.syms,
                symtab.strs,
                sym.st_value,
                // SANITY: We filter out all unsupported symbol types,
                //         so this conversion should always succeed.
                SymType::try_from(sym).unwrap(),
            );
            !matches!(result, Ok(Some(_)))
        })?;
        Ok(str2sym)
    }
}

impl Debug for Cache<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Cache")
    }
}


/// A parser for ELF64 files.
#[derive(Debug)]
pub(crate) struct ElfParser {
    /// A cache for relevant parts of the ELF file.
    // SAFETY: We must not hand out references with a 'static lifetime to
    //         this member. Rather, they should never outlive `self`.
    //         Furthermore, this member has to be listed before `_mmap`
    //         to make sure we never end up with a dangling reference.
    cache: Cache<'static>,
    /// A mapping from section index to decompressed section data.
    // Note that conceptually this member would be best contained in the
    // `Cache` type, however, lifetimes get very hairy once we move it
    // in there. Given that it is an implementation detail, we can live
    // with this slightly counter-intuitive split.
    decompressed: InsertMap<usize, Vec<u8>>,
    /// The memory mapped file.
    _mmap: Mmap,
    /// The path to the ELF file being worked on, if available.
    path: Option<PathBuf>,
}

impl ElfParser {
    /// Create an `ElfParser` from an open file.
    pub(crate) fn open_file<P>(file: &File, path: P) -> Result<Self>
    where
        P: Into<PathBuf>,
    {
        let mmap = Mmap::map(file).context("failed to memory map file")?;
        Ok(Self::from_mmap(mmap, Some(path.into())))
    }

    /// Create an `ElfParser` from mmap'ed data.
    pub(crate) fn from_mmap(mmap: Mmap, path: Option<PathBuf>) -> Self {
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        let elf_data = unsafe { mem::transmute::<&[u8], &'static [u8]>(mmap.deref()) };

        let parser = ElfParser {
            _mmap: mmap,
            decompressed: InsertMap::new(),
            cache: Cache::new(elf_data),
            path,
        };
        parser
    }

    /// Create an `ElfParser` for a path.
    pub(crate) fn open(path: &Path) -> Result<ElfParser> {
        let file =
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        Self::open_file(&file, path)
    }

    /// Retrieve the data corresponding to the ELF section at index
    /// `idx`, optionally decompressing it if it is compressed.
    ///
    /// If the section is compressed the resulting decompressed data
    /// will be cached for the life time of this object.
    pub(crate) fn section_data(&self, idx: usize) -> Result<&[u8]> {
        let (shdr, mut data) = self.cache.section_data_raw(idx)?;

        if shdr.flags() & SHF_COMPRESSED != 0 {
            let data = self.decompressed.get_or_try_insert(idx, || {
                // Compression header is contained in the actual section
                // data.
                let chdr = data
                    .read_pod::<Elf64_Chdr>()
                    .ok_or_invalid_data(|| "failed to read Elf64_Chdr")?;

                let decompressed = match chdr.ch_type {
                    t if t == ELFCOMPRESS_ZLIB => decompress_zlib(data),
                    t if t == ELFCOMPRESS_ZSTD => decompress_zstd(data),
                    _ => Err(Error::with_unsupported(format!(
                        "ELF section is compressed with unknown compression algorithm ({})",
                        chdr.ch_type
                    ))),
                }?;
                debug_assert_eq!(
                    decompressed.len(),
                    chdr.ch_size as usize,
                    "decompressed ELF section data does not have expected length"
                );
                Ok(decompressed)
            })?;
            Ok(data.as_slice())
        } else {
            Ok(data)
        }
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub(crate) fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let index = self.cache.find_section(name)?;
        Ok(index)
    }

    pub(crate) fn find_sym(
        &self,
        addr: Addr,
        opts: &FindSymOpts,
    ) -> Result<Result<ResolvedSym<'_>, Reason>> {
        // ELF doesn't carry any source code or inlining information.
        let _opts = opts;

        let symtab_cache = self.cache.ensure_symtab_cache()?;
        if let Some(sym) = find_sym(
            &symtab_cache.syms,
            symtab_cache.strs,
            addr,
            SymType::Undefined,
        )? {
            return Ok(Ok(sym))
        }

        let dynsym_cache = self.cache.ensure_dynsym_cache()?;
        if let Some(sym) = find_sym(
            &dynsym_cache.syms,
            dynsym_cache.strs,
            addr,
            SymType::Undefined,
        )? {
            return Ok(Ok(sym))
        }

        // At this point we haven't found a symbol for the given
        // address. The emptiness of `dynsym` has no bearing on the
        // reason we report -- for all intents and purposes it is either
        // required or not at all necessary.
        let reason = if symtab_cache.syms.is_empty() {
            Reason::MissingSyms
        } else {
            Reason::UnknownAddr
        };
        Ok(Err(reason))
    }

    /// Calculate the file offset of the given symbol.
    ///
    /// # Notes
    /// It is the caller's responsibility to ensure that the symbol's section
    /// index is not `SHN_UNDEF`.
    fn file_offset(&self, shdrs: ElfN_Shdrs<'_>, sym: &Elf64_Sym) -> Result<Option<u64>> {
        debug_assert_ne!(sym.st_shndx, SHN_UNDEF);

        if sym.st_shndx >= SHN_LORESERVE {
            return Ok(None)
        }

        let shdr = shdrs
            .get(usize::from(sym.st_shndx))
            .ok_or_invalid_input(|| {
                format!(
                    "ELF section index ({}) of symbol at {:#x} out of bounds",
                    sym.st_shndx, sym.st_value
                )
            })?;

        Ok(Some(sym.st_value - shdr.addr() + shdr.offset()))
    }

    fn find_addr_impl<'slf>(
        &'slf self,
        name: &str,
        opts: &FindAddrOpts,
        shdrs: ElfN_Shdrs<'_>,
        syms: &[&'slf Elf64_Sym],
        str2sym: &'slf [(&'slf str, usize)],
    ) -> Result<Vec<SymInfo<'slf>>> {
        let r = find_match_or_lower_bound_by_key(str2sym, name, |&(name, _i)| name);
        match r {
            Some(idx) => {
                let mut found = vec![];
                for (name_visit, sym_i) in str2sym.iter().skip(idx) {
                    if *name_visit != name {
                        break
                    }
                    let sym_ref = &syms.get(*sym_i).ok_or_invalid_input(|| {
                        format!("ELF symbol table index ({sym_i}) out of bounds")
                    })?;
                    if sym_ref.st_shndx != SHN_UNDEF {
                        found.push(SymInfo {
                            name: Cow::Borrowed(name_visit),
                            addr: sym_ref.st_value as Addr,
                            size: sym_ref.st_size as usize,
                            // SANITY: We filter out all unsupported symbol
                            //         types, so this conversion should always
                            //         succeed.
                            sym_type: SymType::try_from(**sym_ref).unwrap(),
                            file_offset: opts
                                .offset_in_file
                                .then(|| self.file_offset(shdrs, sym_ref))
                                .transpose()?
                                .flatten(),
                            obj_file_name: self.path().map(Cow::Borrowed),
                        });
                    }
                }
                Ok(found)
            }
            None => Ok(vec![]),
        }
    }

    pub(crate) fn find_addr<'slf>(
        &'slf self,
        name: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymInfo<'slf>>> {
        let shdrs = self.cache.ensure_shdrs()?;
        let symtab = self.cache.ensure_symtab()?;
        let str2symtab = self.cache.ensure_str2symtab()?;
        let syms = self.find_addr_impl(name, opts, shdrs, symtab, str2symtab)?;
        if !syms.is_empty() {
            return Ok(syms)
        }

        let dynsym = self.cache.ensure_dynsym()?;
        let str2dynsym = self.cache.ensure_str2dynsym()?;
        let syms = self.find_addr_impl(name, opts, shdrs, dynsym, str2dynsym)?;
        Ok(syms)
    }

    fn for_each_sym_impl(
        &self,
        opts: &FindAddrOpts,
        syms: &[&Elf64_Sym],
        str2sym: &[(&str, usize)],
        f: &mut ForEachFn<'_>,
    ) -> Result<()> {
        let shdrs = self.cache.ensure_shdrs()?;

        for (name, idx) in str2sym {
            let sym = &syms
                .get(*idx)
                .ok_or_invalid_input(|| format!("symbol table index ({idx}) out of bounds"))?;
            if sym.matches(opts.sym_type) && sym.st_shndx != SHN_UNDEF {
                let sym_info = SymInfo {
                    name: Cow::Borrowed(name),
                    addr: sym.st_value as Addr,
                    size: sym.st_size as usize,
                    // SANITY: We filter out all unsupported symbol
                    //         types, so this conversion should always
                    //         succeed.
                    sym_type: SymType::try_from(**sym).unwrap(),
                    file_offset: opts
                        .offset_in_file
                        .then(|| self.file_offset(shdrs, sym))
                        .transpose()?
                        .flatten(),
                    obj_file_name: None,
                };
                if let ControlFlow::Break(()) = f(&sym_info) {
                    return Ok(())
                }
            }
        }

        Ok(())
    }

    /// Perform an operation on each symbol.
    #[allow(clippy::needless_borrows_for_generic_args)]
    pub(crate) fn for_each(&self, opts: &FindAddrOpts, f: &mut ForEachFn) -> Result<()> {
        let symtab = self.cache.ensure_symtab()?;
        let str2symtab = self.cache.ensure_str2symtab()?;
        let () = self.for_each_sym_impl(opts, symtab, str2symtab, f)?;

        let dynsym = self.cache.ensure_dynsym()?;
        let str2dynsym = self.cache.ensure_str2dynsym()?;
        let () = self.for_each_sym_impl(opts, dynsym, str2dynsym, f)?;

        Ok(())
    }

    /// Find the file offset of the symbol at address `addr`.
    // If possible, use the constant-time [`file_offset`][Self::file_offset]
    // method instead.
    pub(crate) fn find_file_offset(&self, addr: Addr) -> Result<Option<u64>> {
        let phdrs = self.program_headers()?;
        let offset = phdrs.iter().find_map(|phdr| {
            if phdr.p_type == PT_LOAD {
                if (phdr.p_vaddr..phdr.p_vaddr + phdr.p_memsz).contains(&addr) {
                    return Some(addr - phdr.p_vaddr + phdr.p_offset)
                }
            }
            None
        });
        Ok(offset)
    }

    #[cfg(test)]
    fn get_symbol_name(&self, idx: usize) -> Result<&str> {
        let symtab_cache = self.cache.ensure_symtab_cache()?;
        let sym = self.cache.symbol(idx)?;
        let name = symbol_name(symtab_cache.strs, sym)?;
        Ok(name)
    }

    pub(crate) fn section_headers(&self) -> Result<ElfN_Shdrs<'_>> {
        let shdrs = self.cache.ensure_shdrs()?;
        Ok(shdrs)
    }

    pub(crate) fn program_headers(&self) -> Result<&[Elf64_Phdr]> {
        let phdrs = self.cache.ensure_phdrs()?;
        Ok(phdrs)
    }

    /// Translate a file offset into a virtual offset.
    pub(crate) fn file_offset_to_virt_offset(&self, offset: u64) -> Result<Option<Addr>> {
        let phdrs = self.program_headers()?;
        let addr = phdrs.iter().find_map(|phdr| {
            if phdr.p_type == PT_LOAD {
                if (phdr.p_offset..phdr.p_offset + phdr.p_filesz).contains(&offset) {
                    return Some((offset - phdr.p_offset + phdr.p_vaddr) as Addr)
                }
            }
            None
        });

        Ok(addr)
    }

    #[cfg(test)]
    fn pick_symtab_addr(&self) -> (&str, Addr, usize) {
        let symtab = self.cache.ensure_symtab().unwrap();

        let mut idx = symtab.len() / 2;
        while !symtab[idx].matches(SymType::Function) || symtab[idx].st_shndx == SHN_UNDEF {
            idx += 1;
        }
        let sym = &symtab[idx];
        let addr = sym.st_value;
        let size = sym.st_size;

        let sym_name = self.get_symbol_name(idx).unwrap();
        (
            sym_name,
            addr as Addr,
            usize::try_from(size).unwrap_or(usize::MAX),
        )
    }

    /// Retrieve the path to the file this object operates on.
    #[inline]
    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use super::super::types::SHN_LORESERVE;

    use std::env;
    use std::env::current_exe;
    use std::io::Seek as _;
    use std::io::Write as _;
    use std::mem::size_of;
    use std::slice;

    use tempfile::NamedTempFile;

    use test_log::test;


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
            e_shoff: size_of::<Elf64_Ehdr>() as _,
            e_flags: 0,
            e_ehsize: 64,
            e_phentsize: 56,
            e_phnum: PN_XNUM,
            e_shentsize: 64,
            e_shnum: 0,
            e_shstrndx: 29,
        };
        let ehdr = EhdrExt {
            ehdr: ElfN_Ehdr::B64(&ehdr),
            shnum: 42,
            phnum: 0,
        };
        assert_ne!(format!("{ehdr:?}"), "");

        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert_ne!(format!("{parser:?}"), "");
    }

    /// Check that our `ElfParser` can handle more than 0xff00 section
    /// headers and more than 0xffff program headers properly.
    #[test]
    fn excessive_section_and_program_headers() {
        const SHNUM: u16 = (SHN_LORESERVE + 0x42) as _;
        const PHNUM: u32 = 0xffff + 0x43;

        #[repr(C)]
        struct Elf {
            ehdr: Elf64_Ehdr,
            shdrs: [Elf64_Shdr; 2],
        }

        // Data extracted from an actual binary; section header related
        // information adjusted.
        let elf = Elf {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: 64,
                e_shoff: size_of::<Elf64_Ehdr>() as _,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: PN_XNUM,
                e_shentsize: 64,
                e_shnum: 0,
                e_shstrndx: 29,
            },
            shdrs: [
                Elf64_Shdr {
                    sh_name: 0,
                    sh_type: 0,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: 0,
                    sh_size: SHNUM.into(),
                    sh_link: 0,
                    sh_info: PHNUM,
                    sh_addralign: 0,
                    sh_entsize: 0,
                },
                Elf64_Shdr {
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
                },
            ],
        };

        let mut file = NamedTempFile::new().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        let parser = ElfParser::open_file(file.as_file(), file.path()).unwrap();
        let ehdr = parser.cache.ensure_ehdr().unwrap();
        assert_eq!(ehdr.shnum, usize::from(SHNUM));
        assert_eq!(ehdr.phnum, usize::try_from(PHNUM).unwrap());
    }

    /// Test that our `ElfParser` can handle a `shstrndx` larger than
    /// 0xff00.
    #[test]
    fn large_e_shstrndx() {
        const SHSTRNDX: u16 = (SHN_LORESERVE + 0x42) as _;

        #[repr(C)]
        struct Elf {
            ehdr: Elf64_Ehdr,
            shdrs: [Elf64_Shdr; 1],
        }

        // Data extracted from an actual binary; `e_shstrndx` related
        // information adjusted.
        let elf = Elf {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: 64,
                e_shoff: size_of::<Elf64_Ehdr>() as _,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: 13,
                e_shentsize: 64,
                e_shnum: 0,
                e_shstrndx: SHN_XINDEX,
            },
            shdrs: [Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: SHSTRNDX.into(),
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            }],
        };

        let mut file = NamedTempFile::new().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        let parser = ElfParser::open_file(file.as_file(), file.path()).unwrap();
        let ehdr = parser.cache.ensure_ehdr().unwrap();
        let shstrndx = parser.cache.shstrndx(ehdr.ehdr).unwrap();
        assert_eq!(shstrndx, usize::from(SHSTRNDX));
    }


    #[test]
    fn test_elf64_parser() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());
    }

    #[test]
    fn test_elf64_symtab() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (name, addr, size) = parser.pick_symtab_addr();

        let sym = parser.find_sym(addr, &FindSymOpts::Basic).unwrap().unwrap();
        assert_eq!(sym.addr, addr);
        assert_eq!(sym.name, name);
        assert_eq!(sym.size, Some(size));
    }

    #[test]
    fn elf64_lookup_symbol_random() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (name, addr, size) = parser.pick_symtab_addr();

        println!("{name}");
        let opts = FindAddrOpts::default();
        let addr_r = parser.find_addr(name, &opts).unwrap();
        assert_eq!(addr_r.len(), 1);
        assert!(addr_r.iter().any(|x| x.addr == addr && x.size == size));
    }

    /// Validate our two methods of symbol file offset calculation against each
    /// other.
    #[test]
    fn file_offset_calculation() {
        fn test(path: &Path) {
            let opts = FindAddrOpts {
                offset_in_file: true,
                sym_type: SymType::Function,
            };
            let parser = ElfParser::open(path).unwrap();
            let () = parser
                .for_each(&opts, &mut |sym| {
                    let file_offset = parser.find_file_offset(sym.addr).unwrap();
                    assert_eq!(file_offset, sym.file_offset);
                    ControlFlow::Continue(())
                })
                .unwrap();
        }

        let exe = current_exe().unwrap();
        test(&exe);

        let so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        test(&so);
    }

    /// Check that we can correctly convert a file offset into a virtual
    /// offset.
    ///
    /// This is a regression test for the case that a program header
    /// with a memory size greater than file size is located before a
    /// program header that would otherwise match the file offset. Refer
    /// to commit 1a4e10740652 ("Use file size in file offset -> virtual
    /// offset translation").
    #[test]
    fn virtual_offset_calculation() {
        #[repr(C)]
        struct Elf {
            ehdr: Elf64_Ehdr,
            phdrs: [Elf64_Phdr; 2],
        }

        // Data is mostly made up, except for relevant program headers,
        // which were copied from a real binary.
        let elf = Elf {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: size_of::<Elf64_Ehdr>() as _,
                e_shoff: 0,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: 2,
                e_shentsize: 0,
                e_shnum: 1,
                e_shstrndx: 0,
            },
            phdrs: [
                Elf64_Phdr {
                    p_type: 1,
                    p_flags: 6,
                    p_offset: 455231872,
                    p_vaddr: 457337216,
                    p_paddr: 457337216,
                    p_filesz: 3422344,
                    p_memsz: 13261132,
                    p_align: 4096,
                },
                Elf64_Phdr {
                    p_type: 1,
                    p_flags: 5,
                    p_offset: 459276288,
                    p_vaddr: 471859200,
                    p_paddr: 471859200,
                    p_filesz: 77813932,
                    p_memsz: 77813932,
                    p_align: 2097152,
                },
            ],
        };

        let mut file = NamedTempFile::new().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        let parser = ElfParser::open_file(file.as_file(), file.path()).unwrap();
        // A file offset as produced by normalization.
        let file_offset = 0x1b63b4d0;
        let virt_offset = parser
            .file_offset_to_virt_offset(file_offset)
            .unwrap()
            .unwrap();
        assert_eq!(virt_offset, 0x1c23b4d0);
    }

    /// Make sure that we can look up a symbol in an ELF file.
    #[test]
    fn lookup_symbol() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let opts = FindAddrOpts::default();
        let syms = parser.find_addr("factorial", &opts).unwrap();
        assert_eq!(syms.len(), 1);
        let sym = &syms[0];
        assert_eq!(sym.name, "factorial");
        assert_eq!(sym.addr, 0x2000100);

        let syms = parser.find_addr("factorial_wrapper", &opts).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "factorial_wrapper");
        assert_eq!(syms[1].name, "factorial_wrapper");
        assert_ne!(syms[0].addr, syms[1].addr);
    }

    /// Make sure that we do not report a symbol if there is no conceivable
    /// match.
    #[test]
    fn lookup_symbol_without_match() {
        let strtab = b"\x00_glapi_tls_Context\x00_glapi_get_dispatch_table_size\x00";
        let symtab = [
            &Elf64_Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            &Elf64_Sym {
                st_name: 0x1,
                // Note: the type is *not* `STT_FUNC`.
                st_info: 0x16,
                st_other: 0x0,
                st_shndx: 0x14,
                st_value: 0x8,
                st_size: 0x8,
            },
            &Elf64_Sym {
                st_name: 0x21,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xe,
                st_value: 0x1a4a0,
                st_size: 0xa,
            },
        ];

        let result = find_sym(&symtab, strtab, 0x10d20, SymType::Function).unwrap();
        assert_eq!(result, None);
    }

    /// Check that we report a symbol with an unknown `st_size` value is
    /// reported, if it is the only conceivable match.
    #[test]
    fn lookup_symbol_with_unknown_size() {
        fn test(symtab: &[&Elf64_Sym]) {
            let strtab = b"\x00__libc_init_first\x00versionsort64\x00";
            let sym = find_sym(symtab, strtab, 0x29d00, SymType::Function)
                .unwrap()
                .unwrap();
            assert_eq!(sym.name, "__libc_init_first");
            assert_eq!(sym.addr, 0x29d00);
            assert_eq!(sym.size, None);

            // Because the symbol has a size of 0 and is the only conceivable
            // match, we report it on the basis that ELF reserves these for "no
            // size or an unknown size" cases.
            let sym = find_sym(symtab, strtab, 0x29d90, SymType::Function)
                .unwrap()
                .unwrap();
            assert_eq!(sym.name, "__libc_init_first");
            assert_eq!(sym.addr, 0x29d00);
            assert_eq!(sym.size, None);

            // Note that despite of the first symbol (the invalid one; present
            // by default and reserved by ELF), is not being reported here
            // because it has an `st_shndx` value of `SHN_UNDEF`.
            let result = find_sym(symtab, strtab, 0x1, SymType::Function).unwrap();
            assert_eq!(result, None);
        }

        let symtab = [
            &Elf64_Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            &Elf64_Sym {
                st_name: 0x1,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xf,
                st_value: 0x29d00,
                st_size: 0x0,
            },
            &Elf64_Sym {
                st_name: 0xdeadbeef,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xf,
                st_value: 0x29dc0,
                st_size: 0x148,
            },
        ];

        test(&symtab);
        test(&symtab[0..2]);
    }

    /// Check that we can properly read empty symbol tables, even if not
    /// correctly aligned, as long as it is empty.
    #[test]
    fn empty_symbol_table_reading() {
        let ehdr = Elf64_Ehdr {
            e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            e_type: 3,
            e_machine: 62,
            e_version: 1,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 3,
            e_shstrndx: 1,
        };
        let ehdr = EhdrExt {
            ehdr: ElfN_Ehdr::B64(&ehdr),
            shnum: 3,
            phnum: 0,
        };
        let shdrs = [
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            Elf64_Shdr {
                sh_name: 10,
                // The section contains no actual data.
                sh_type: SHT_NOBITS,
                sh_flags: 0,
                sh_addr: 0,
                // One byte into an aligned buffer we will always end up at an
                // unaligned address. This should result in a failed read of an
                // Elf64_Sym slice, if we were to actually read data (which we
                // should not).
                sh_offset: 1,
                sh_size: mem::size_of::<Elf64_Sym>() as _,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        ];
        let mut aligned_data = [0u8; 1024].as_slice();
        let () = aligned_data.align(8).unwrap();

        let cache = Cache {
            elf_data: aligned_data,
            ehdr: OnceCell::from(ehdr),
            shdrs: OnceCell::from(ElfN_Shdrs::B64(shdrs.as_slice())),
            shstrtab: OnceCell::from(b".shstrtab\x00.symtab\x00".as_slice()),
            phdrs: OnceCell::new(),
            symtab: OnceCell::new(),
            dynsym: OnceCell::new(),
        };

        assert_eq!(cache.find_section(".symtab").unwrap(), Some(2));

        let symtab = cache.ensure_symtab().unwrap();
        assert!(symtab.is_empty());
    }
}

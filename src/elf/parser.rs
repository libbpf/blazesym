use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem;
use std::ops::Deref as _;
use std::path::Path;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::mmap::Mmap;
use crate::once::OnceCell;
use crate::symbolize::Reason;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;
use crate::SymType;

use super::types::Elf64_Ehdr;
use super::types::Elf64_Phdr;
use super::types::Elf64_Shdr;
use super::types::Elf64_Sym;
use super::types::PN_XNUM;
use super::types::PT_LOAD;
use super::types::SHN_UNDEF;
use super::types::SHN_XINDEX;


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
) -> Result<Option<(&'mmap str, Addr, usize)>> {
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
                // size" (see elf(5)). We take our changes and report these on a
                // best-effort basis.
                if sym.matches(type_)
                    && sym.st_shndx != SHN_UNDEF
                    && (sym.st_size == 0 || addr < sym.st_value + sym.st_size)
                {
                    let name = symbol_name(strtab, sym)?;
                    let addr = sym.st_value as Addr;
                    let size = usize::try_from(sym.st_size).unwrap_or(usize::MAX);
                    return Ok(Some((name, addr, size)))
                }
            }
            Ok(None)
        }
    }
}


#[derive(Clone, Copy, Debug)]
struct EhdrExt<'mmap> {
    /// The ELF header.
    ehdr: &'mmap Elf64_Ehdr,
    /// Override of `ehdr.e_shnum`, handling of which is special-cased by
    /// the ELF standard.
    shnum: usize,
    /// Override of `ehdr.e_phnum`, handling of which is special-cased by
    /// the ELF standard.
    phnum: usize,
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
    fn new(syms: Vec<&'mmap Elf64_Sym>, strs: &'mmap [u8]) -> Self {
        Self {
            syms: syms.into_boxed_slice(),
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
                    .ok_or_invalid_input(|| "string table index out of bounds")?
                    .read_cstr()
                    .ok_or_invalid_input(|| "no valid string found in string table")?
                    .to_str()
                    .map_err(Error::with_invalid_data)
                    .context("invalid symbol name")?;
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
    shdrs: OnceCell<&'mmap [Elf64_Shdr]>,
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
    /// `idx`.
    fn section_data(&self, idx: usize) -> Result<&'mmap [u8]> {
        let shdrs = self.ensure_shdrs()?;
        let section = shdrs
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF section index ({idx}) out of bounds"))?;

        let data = self
            .elf_data
            .get(section.sh_offset as usize..)
            .ok_or_invalid_data(|| "failed to read section data: invalid offset")?
            .read_slice(section.sh_size as usize)
            .ok_or_invalid_data(|| "failed to read section data: invalid size")?;
        Ok(data)
    }

    /// Read the very first section header.
    ///
    /// ELF contains a couple of clauses that special case data ranges
    /// of certain member variables to reference data from this header,
    /// which otherwise is zeroed out.
    #[inline]
    fn read_first_shdr(&self, ehdr: &Elf64_Ehdr) -> Result<&'mmap Elf64_Shdr> {
        let shdr = self
            .elf_data
            .get(ehdr.e_shoff as usize..)
            .ok_or_invalid_data(|| "Elf64_Ehdr::e_shoff is invalid")?
            .read_pod_ref::<Elf64_Shdr>()
            .ok_or_invalid_data(|| "failed to read Elf64_Shdr")?;
        Ok(shdr)
    }

    fn parse_ehdr(&self) -> Result<EhdrExt<'mmap>> {
        let mut elf_data = self.elf_data;
        let ehdr = elf_data
            .read_pod_ref::<Elf64_Ehdr>()
            .ok_or_invalid_data(|| "failed to read Elf64_Ehdr")?;
        if !(ehdr.e_ident[0] == 0x7f
            && ehdr.e_ident[1] == b'E'
            && ehdr.e_ident[2] == b'L'
            && ehdr.e_ident[3] == b'F')
        {
            return Err(Error::with_invalid_data(format!(
                "encountered unexpected e_ident: {:x?}",
                &ehdr.e_ident[0..4]
            )))
        }

        // "If the number of entries in the section header table is larger than
        // or equal to SHN_LORESERVE, e_shnum holds the value zero and the real
        // number of entries in the section header table is held in the sh_size
        // member of the initial entry in section header table."
        let shnum = if ehdr.e_shnum == 0 {
            let shdr = self.read_first_shdr(ehdr)?;
            usize::try_from(shdr.sh_size).ok().ok_or_invalid_data(|| {
                format!(
                    "ELF file contains unsupported number of sections ({})",
                    shdr.sh_size
                )
            })?
        } else {
            ehdr.e_shnum.into()
        };

        // "If the number of entries in the program header table is
        // larger than or equal to PN_XNUM (0xffff), this member holds
        // PN_XNUM (0xffff) and the real number of entries in the
        // program header table is held in the sh_info member of the
        // initial entry in section header table."
        let phnum = if ehdr.e_phnum == PN_XNUM {
            let shdr = self.read_first_shdr(ehdr)?;
            usize::try_from(shdr.sh_info).ok().ok_or_invalid_data(|| {
                format!(
                    "ELF file contains unsupported number of program headers ({})",
                    shdr.sh_info
                )
            })?
        } else {
            ehdr.e_phnum.into()
        };

        let ehdr = EhdrExt { ehdr, shnum, phnum };
        Ok(ehdr)
    }

    fn ensure_ehdr(&self) -> Result<&EhdrExt<'mmap>> {
        self.ehdr.get_or_try_init(|| self.parse_ehdr())
    }

    fn parse_shdrs(&self) -> Result<&'mmap [Elf64_Shdr]> {
        let ehdr = self.ensure_ehdr()?;
        let shdrs = self
            .elf_data
            .get(ehdr.ehdr.e_shoff as usize..)
            .ok_or_invalid_data(|| "Elf64_Ehdr::e_shoff is invalid")?
            .read_pod_slice_ref::<Elf64_Shdr>(ehdr.shnum)
            .ok_or_invalid_data(|| "failed to read Elf64_Shdr")?;
        Ok(shdrs)
    }

    fn ensure_shdrs(&self) -> Result<&'mmap [Elf64_Shdr]> {
        self.shdrs.get_or_try_init(|| self.parse_shdrs()).copied()
    }

    fn parse_phdrs(&self) -> Result<&'mmap [Elf64_Phdr]> {
        let ehdr = self.ensure_ehdr()?;
        let phdrs = self
            .elf_data
            .get(ehdr.ehdr.e_phoff as usize..)
            .ok_or_invalid_data(|| "Elf64_Ehdr::e_phoff is invalid")?
            .read_pod_slice_ref::<Elf64_Phdr>(ehdr.phnum)
            .ok_or_invalid_data(|| "failed to read Elf64_Phdr")?;
        Ok(phdrs)
    }

    fn ensure_phdrs(&self) -> Result<&'mmap [Elf64_Phdr]> {
        self.phdrs.get_or_try_init(|| self.parse_phdrs()).copied()
    }

    fn shstrndx(&self, ehdr: &Elf64_Ehdr) -> Result<usize> {
        // "If the index of section name string table section is larger
        // than or equal to SHN_LORESERVE (0xff00), this member holds
        // SHN_XINDEX (0xffff) and  the real index of the section name
        // string table section is held in the sh_link member of the
        // initial entry in section header table."
        let shstrndx = if ehdr.e_shstrndx == SHN_XINDEX {
            let shdr = self.read_first_shdr(ehdr)?;
            shdr.sh_link
        } else {
            u32::from(ehdr.e_shstrndx)
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

        let sect = shdrs
            .get(idx)
            .ok_or_invalid_input(|| "ELF section index out of bounds")?;
        let name = shstrtab
            .get(sect.sh_name as usize..)
            .ok_or_invalid_input(|| "string table index out of bounds")?
            .read_cstr()
            .ok_or_invalid_input(|| "no valid string found in string table")?
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

    fn parse_syms(&self, section: &str) -> Result<Vec<&'mmap Elf64_Sym>> {
        let idx = if let Some(idx) = self.find_section(section)? {
            idx
        } else {
            // The symbol table does not exists. Fake an empty one.
            return Ok(Vec::new())
        };
        let mut syms = self.section_data(idx)?;

        if syms.len() % mem::size_of::<Elf64_Sym>() != 0 {
            return Err(Error::with_invalid_data(
                "size of symbol table section is invalid",
            ))
        }

        let count = syms.len() / mem::size_of::<Elf64_Sym>();
        let mut syms = syms
            .read_pod_slice_ref::<Elf64_Sym>(count)
            .ok_or_invalid_data(|| "failed to read symbol table contents")?
            .iter()
            // Filter out any symbols that we do not support.
            .filter(|sym| sym.matches(SymType::Undefined))
            .collect::<Vec<&Elf64_Sym>>();
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
    /// The memory mapped file.
    _mmap: Mmap,
}

impl ElfParser {
    /// Create an `ElfParser` from an open file.
    pub fn open_file(file: &File) -> Result<ElfParser> {
        Mmap::map(file)
            .map(Self::from_mmap)
            .context("failed to memory map file")
    }

    /// Create an `ElfParser` from mmap'ed data.
    pub fn from_mmap(mmap: Mmap) -> ElfParser {
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        let elf_data = unsafe { mem::transmute(mmap.deref()) };

        let parser = ElfParser {
            _mmap: mmap,
            cache: Cache::new(elf_data),
        };
        parser
    }

    /// Create an `ElfParser` for a path.
    pub fn open(filename: &Path) -> Result<ElfParser> {
        let file = File::open(filename)
            .with_context(|| format!("failed to open {}", filename.display()))?;
        Self::open_file(&file)
    }

    /// Retrieve the data corresponding to the ELF section at index `idx`.
    pub fn section_data(&self, idx: usize) -> Result<&[u8]> {
        self.cache.section_data(idx)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let index = self.cache.find_section(name)?;
        Ok(index)
    }

    pub fn find_sym(
        &self,
        addr: Addr,
        type_: SymType,
    ) -> Result<Result<(&str, Addr, usize), Reason>> {
        let symtab_cache = self.cache.ensure_symtab_cache()?;
        if let Some(sym) = find_sym(&symtab_cache.syms, symtab_cache.strs, addr, type_)? {
            return Ok(Ok(sym))
        }

        let dynsym_cache = self.cache.ensure_dynsym_cache()?;
        if let Some(sym) = find_sym(&dynsym_cache.syms, dynsym_cache.strs, addr, type_)? {
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
    fn file_offset(&self, shdrs: &[Elf64_Shdr], sym: &Elf64_Sym) -> Result<u64> {
        debug_assert_ne!(sym.st_shndx, SHN_UNDEF);

        let section = shdrs
            .get(usize::from(sym.st_shndx))
            .ok_or_invalid_input(|| {
                format!(
                    "ELF section index ({}) of symbol at {:#x} out of bounds",
                    sym.st_shndx, sym.st_value
                )
            })?;
        Ok(sym.st_value - section.sh_addr + section.sh_offset)
    }

    fn find_addr_impl<'slf>(
        &'slf self,
        name: &str,
        opts: &FindAddrOpts,
        shdrs: &'slf [Elf64_Shdr],
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
                        format!("symbol table index ({sym_i}) out of bounds")
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
                                .transpose()?,
                            obj_file_name: None,
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

    fn for_each_sym_impl<F, R>(
        &self,
        opts: &FindAddrOpts,
        syms: &[&Elf64_Sym],
        str2sym: &[(&str, usize)],
        mut r: R,
        mut f: F,
    ) -> Result<R>
    where
        F: FnMut(R, &SymInfo<'_>) -> R,
    {
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
                        .transpose()?,
                    obj_file_name: None,
                };
                r = f(r, &sym_info)
            }
        }

        Ok(r)
    }

    /// Perform an operation on each symbol.
    pub(crate) fn for_each_sym<F, R>(&self, opts: &FindAddrOpts, r: R, mut f: F) -> Result<R>
    where
        F: FnMut(R, &SymInfo<'_>) -> R,
    {
        let symtab = self.cache.ensure_symtab()?;
        let str2symtab = self.cache.ensure_str2symtab()?;
        let r = self.for_each_sym_impl(opts, symtab, str2symtab, r, &mut f)?;

        let dynsym = self.cache.ensure_dynsym()?;
        let str2dynsym = self.cache.ensure_str2dynsym()?;
        let r = self.for_each_sym_impl(opts, dynsym, str2dynsym, r, &mut f)?;

        Ok(r)
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

    pub(crate) fn section_headers(&self) -> Result<&[Elf64_Shdr]> {
        let phdrs = self.cache.ensure_shdrs()?;
        Ok(phdrs)
    }

    pub(crate) fn program_headers(&self) -> Result<&[Elf64_Phdr]> {
        let phdrs = self.cache.ensure_phdrs()?;
        Ok(phdrs)
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

    use tempfile::tempfile;

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
            ehdr: &ehdr,
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

        let mut file = tempfile().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        let parser = ElfParser::open_file(&file).unwrap();
        let ehdr = parser.cache.ensure_ehdr().unwrap();
        assert_eq!(ehdr.shnum, SHNUM.into());
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

        let mut file = tempfile().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        let parser = ElfParser::open_file(&file).unwrap();
        let ehdr = parser.cache.ensure_ehdr().unwrap();
        let shstrndx = parser.cache.shstrndx(ehdr.ehdr).unwrap();
        assert_eq!(shstrndx, SHSTRNDX.into());
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

        let sym = parser.find_sym(addr, SymType::Function).unwrap().unwrap();
        let (name_ret, addr_ret, size_ret) = sym;
        assert_eq!(addr_ret, addr);
        assert_eq!(name_ret, name);
        assert_eq!(size_ret, size);
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
        let bin_name = current_exe().unwrap();
        let opts = FindAddrOpts {
            offset_in_file: true,
            sym_type: SymType::Function,
        };
        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let () = parser
            .for_each_sym(&opts, (), |(), sym| {
                let file_offset = parser.find_file_offset(sym.addr).unwrap();
                assert_eq!(file_offset, sym.file_offset);
            })
            .unwrap();
    }

    /// Make sure that we can look up a symbol in an ELF file.
    #[test]
    fn lookup_symbol() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");

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
            let result = find_sym(symtab, strtab, 0x29d00, SymType::Function)
                .unwrap()
                .unwrap();
            assert_eq!(result, ("__libc_init_first", 0x29d00, 0x0));

            // Because the symbol has a size of 0 and is the only conceivable
            // match, we report it on the basis that ELF reserves these for "no
            // size or an unknown size" cases.
            let result = find_sym(symtab, strtab, 0x29d90, SymType::Function)
                .unwrap()
                .unwrap();
            assert_eq!(result, ("__libc_init_first", 0x29d00, 0x0));

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
}

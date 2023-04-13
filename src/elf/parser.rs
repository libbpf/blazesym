use std::cell::RefCell;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::mem;
use std::ops::Deref as _;
#[cfg(test)]
use std::path::Path;

use regex::Regex;

use crate::mmap::Mmap;
use crate::util::search_address_opt_key;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::FindAddrOpts;
use crate::SymbolInfo;
use crate::SymbolType;

use super::types::Elf64_Ehdr;
use super::types::Elf64_Phdr;
use super::types::Elf64_Shdr;
use super::types::Elf64_Sym;
use super::types::SHN_UNDEF;
#[cfg(test)]
use super::types::STT_FUNC;


struct Cache<'mmap> {
    /// A slice of the raw ELF data that we are about to parse.
    elf_data: &'mmap [u8],
    /// The cached ELF header.
    ehdr: Option<&'mmap Elf64_Ehdr>,
    /// The cached ELF section headers.
    shdrs: Option<&'mmap [Elf64_Shdr]>,
    shstrtab: Option<&'mmap [u8]>,
    /// The cached ELF program headers.
    phdrs: Option<&'mmap [Elf64_Phdr]>,
    symtab: Option<Vec<&'mmap Elf64_Sym>>, // in address order
    /// The cached ELF string table.
    strtab: Option<&'mmap [u8]>,
    str2symtab: Option<Vec<(&'mmap str, usize)>>, // strtab offset to symtab in the dictionary order
}

impl<'mmap> Cache<'mmap> {
    /// Create a new `Cache` using the provided raw ELF object data.
    fn new(elf_data: &'mmap [u8]) -> Self {
        Self {
            elf_data,
            ehdr: None,
            shdrs: None,
            shstrtab: None,
            phdrs: None,
            symtab: None,
            strtab: None,
            str2symtab: None,
        }
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`.
    fn section_data(&mut self, idx: usize) -> Result<&'mmap [u8], Error> {
        let shdrs = self.ensure_shdrs()?;
        let section = shdrs.get(idx).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("ELF section index ({idx}) out of bounds"),
            )
        })?;

        let data = self
            .elf_data
            .get(section.sh_offset as usize..)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "failed to read section data: invalid offset",
                )
            })?
            .read_slice(section.sh_size as usize)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "failed to read section data: invalid size",
                )
            })?;
        Ok(data)
    }

    fn ensure_ehdr(&mut self) -> Result<&'mmap Elf64_Ehdr, Error> {
        if let Some(ehdr) = self.ehdr {
            return Ok(ehdr)
        }

        let mut elf_data = self.elf_data;
        let ehdr = elf_data
            .read_pod_ref::<Elf64_Ehdr>()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "failed to read Elf64_Ehdr"))?;
        if !(ehdr.e_ident[0] == 0x7f
            && ehdr.e_ident[1] == b'E'
            && ehdr.e_ident[2] == b'L'
            && ehdr.e_ident[3] == b'F')
        {
            return Err(Error::new(ErrorKind::InvalidData, "e_ident is wrong"))
        }
        self.ehdr = Some(ehdr);
        Ok(ehdr)
    }

    fn ensure_shdrs(&mut self) -> Result<&'mmap [Elf64_Shdr], Error> {
        if let Some(shdrs) = self.shdrs {
            return Ok(shdrs)
        }

        let ehdr = self.ensure_ehdr()?;
        let shdrs = self
            .elf_data
            .get(ehdr.e_shoff as usize..)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Elf64_Ehdr::e_shoff is invalid"))?
            .read_pod_slice_ref::<Elf64_Shdr>(ehdr.e_shnum.into())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "failed to read Elf64_Shdr"))?;
        self.shdrs = Some(shdrs);
        Ok(shdrs)
    }

    fn ensure_phdrs(&mut self) -> Result<&'mmap [Elf64_Phdr], Error> {
        if let Some(phdrs) = self.phdrs {
            return Ok(phdrs)
        }

        let ehdr = self.ensure_ehdr()?;
        let phdrs = self
            .elf_data
            .get(ehdr.e_phoff as usize..)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Elf64_Ehdr::e_phoff is invalid"))?
            .read_pod_slice_ref::<Elf64_Phdr>(ehdr.e_phnum.into())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "failed to read Elf64_Phdr"))?;
        self.phdrs = Some(phdrs);
        Ok(phdrs)
    }

    fn ensure_shstrtab(&mut self) -> Result<&'mmap [u8], Error> {
        if let Some(shstrtab) = self.shstrtab {
            return Ok(shstrtab)
        }

        let ehdr = self.ensure_ehdr()?;
        let shstrndx = ehdr.e_shstrndx;
        let shstrtab = self.section_data(shstrndx as usize)?;
        self.shstrtab = Some(shstrtab);
        Ok(shstrtab)
    }

    /// Get the name of the section at a given index.
    fn section_name(&mut self, idx: usize) -> Result<&'mmap str, Error> {
        let shdrs = self.ensure_shdrs()?;
        let shstrtab = self.ensure_shstrtab()?;

        let sect = shdrs.get(idx).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "ELF section index out of bounds")
        })?;
        let name = shstrtab
            .get(sect.sh_name as usize..)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "string table index out of bounds"))?
            .read_cstr()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "no valid string found in string table",
                )
            })?
            .to_str()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid section name"))?;
        Ok(name)
    }

    fn symbol(&mut self, idx: usize) -> Result<&'mmap Elf64_Sym, Error> {
        let () = self.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = self.symtab.as_ref().unwrap();
        let symbol = symtab.get(idx).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("ELF symbol index ({idx}) out of bounds"),
            )
        })?;

        Ok(symbol)
    }

    fn symbol_name(&mut self, sym: &Elf64_Sym) -> Result<&'mmap str, Error> {
        let strtab = self.ensure_strtab()?;

        let name = strtab
            .get(sym.st_name as usize..)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "string table index out of bounds"))?
            .read_cstr()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "no valid string found in string table",
                )
            })?
            .to_str()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid symbol name"))?;

        Ok(name)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    fn find_section(&mut self, name: &str) -> Result<usize, Error> {
        let ehdr = self.ensure_ehdr()?;
        for i in 1..ehdr.e_shnum.into() {
            if self.section_name(i)? == name {
                return Ok(i)
            }
        }
        Err(Error::new(
            ErrorKind::NotFound,
            format!("unable to find ELF section: {name}"),
        ))
    }

    // Note: This function should really return a reference to
    //       `self.symtab`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_symtab(&mut self) -> Result<(), Error> {
        if self.symtab.is_some() {
            return Ok(())
        }

        let idx = if let Ok(idx) = self.find_section(".symtab") {
            idx
        } else {
            self.find_section(".dynsym")?
        };
        let mut symtab = self.section_data(idx)?;

        if symtab.len() % mem::size_of::<Elf64_Sym>() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "size of symbol table section is invalid",
            ))
        }

        let count = symtab.len() / mem::size_of::<Elf64_Sym>();
        let mut symtab = symtab
            .read_pod_slice_ref::<Elf64_Sym>(count)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "failed to read symbol table contents",
                )
            })?
            .iter()
            .collect::<Vec<&Elf64_Sym>>();
        let () = symtab.sort_by_key(|x| x.st_value);

        self.symtab = Some(symtab);
        Ok(())
    }

    fn ensure_strtab(&mut self) -> Result<&'mmap [u8], Error> {
        if let Some(strtab) = self.strtab {
            return Ok(strtab)
        }

        let idx = if let Ok(idx) = self.find_section(".strtab") {
            idx
        } else {
            self.find_section(".dynstr")?
        };
        let strtab = self.section_data(idx)?;
        self.strtab = Some(strtab);
        Ok(strtab)
    }

    // Note: This function should really return a reference to
    //       `self.str2symtab`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_str2symtab(&mut self) -> Result<(), Error> {
        if self.str2symtab.is_some() {
            return Ok(())
        }

        let strtab = self.ensure_strtab()?;
        let () = self.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = self.symtab.as_ref().unwrap();

        let mut str2symtab = symtab
            .iter()
            .enumerate()
            .map(|(i, sym)| {
                let name = strtab
                    .get(sym.st_name as usize..)
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "string table index out of bounds")
                    })?
                    .read_cstr()
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidInput,
                            "no valid string found in string table",
                        )
                    })?
                    .to_str()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid symbol name"))?;
                Ok((name, i))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let () = str2symtab.sort_by_key(|&(name, _i)| name);

        self.str2symtab = Some(str2symtab);
        Ok(())
    }
}

impl Debug for Cache<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Cache")
    }
}


/// A parser for ELF64 files.
#[derive(Debug)]
pub struct ElfParser {
    /// A cache for relevant parts of the ELF file.
    /// SAFETY: We must not hand out references with a 'static lifetime to
    ///         this member. Rather, they should never outlive `self`.
    ///         Furthermore, this member has to be listed before `mmap`
    ///         to make sure we never end up with a dangling reference.
    cache: RefCell<Cache<'static>>,
    /// The memory mapped file.
    _mmap: Mmap,
}

impl ElfParser {
    pub fn open_file(file: File) -> Result<ElfParser, Error> {
        let mmap = Mmap::map(&file)?;
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        let elf_data = unsafe { std::mem::transmute(mmap.deref()) };

        let parser = ElfParser {
            _mmap: mmap,
            cache: RefCell::new(Cache::new(elf_data)),
        };
        Ok(parser)
    }

    #[cfg(test)]
    pub fn open(filename: &Path) -> Result<ElfParser, Error> {
        let file = File::open(filename)?;
        let parser = Self::open_file(file);
        if let Ok(parser) = parser {
            Ok(parser)
        } else {
            parser
        }
    }

    pub fn get_elf_file_type(&self) -> Result<u16, Error> {
        let mut cache = self.cache.borrow_mut();
        let ehdr = cache.ensure_ehdr()?;

        Ok(ehdr.e_type)
    }

    /// Retrieve the data corresponding to the ELF section at index `idx`.
    pub fn section_data(&self, idx: usize) -> Result<&[u8], Error> {
        let mut cache = self.cache.borrow_mut();
        cache.section_data(idx)
    }

    /// Read the raw data of the section of a given index.
    #[cfg(test)]
    pub fn read_section_raw(&self, sect_idx: usize) -> Result<&[u8], Error> {
        let mut cache = self.cache.borrow_mut();
        cache.section_data(sect_idx)
    }

    pub fn get_section_size(&self, sect_idx: usize) -> Result<usize, Error> {
        let mut cache = self.cache.borrow_mut();
        let shdrs = cache.ensure_shdrs()?;
        let sect = shdrs.get(sect_idx).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "ELF section index out of bounds")
        })?;
        Ok(sect.sh_size as usize)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub fn find_section(&self, name: &str) -> Result<usize, Error> {
        let mut cache = self.cache.borrow_mut();
        let index = cache.find_section(name)?;
        Ok(index)
    }

    pub fn find_symbol(&self, address: Addr, st_type: u8) -> Result<(&str, Addr), Error> {
        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();

        let idx_r = search_address_opt_key(symtab, address, &|sym: &&Elf64_Sym| {
            if sym.st_info & 0xf != st_type || sym.st_shndx == SHN_UNDEF {
                None
            } else {
                Some(sym.st_value as Addr)
            }
        });
        if idx_r.is_none() {
            return Err(Error::new(
                ErrorKind::NotFound,
                "Does not found a symbol for the given address",
            ))
        }
        let idx = idx_r.unwrap();

        let sym = cache.symbol(idx)?;
        let name = cache.symbol_name(sym)?;
        Ok((name, sym.st_value as Addr))
    }

    pub(crate) fn find_address(
        &self,
        name: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"))
        }

        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab()?;
        let () = cache.ensure_str2symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();
        // SANITY: The above `ensure_str2symtab` ensures we have
        //         `str2symtab` available.
        let str2symtab = cache.str2symtab.as_ref().unwrap();

        let r = str2symtab.binary_search_by_key(&name.to_string(), |&(name, _i)| name.to_string());

        match r {
            Ok(str2sym_i) => {
                let mut idx = str2sym_i;
                while idx > 0 {
                    let name_seek = str2symtab[idx].0;
                    if !name_seek.eq(name) {
                        idx += 1;
                        break
                    }
                    idx -= 1;
                }

                let mut found = vec![];
                for (name_visit, sym_i) in str2symtab.iter().skip(idx) {
                    if !(*name_visit).eq(name) {
                        break
                    }
                    let sym_ref = &symtab[*sym_i];
                    if sym_ref.st_shndx != SHN_UNDEF {
                        found.push(SymbolInfo {
                            name: name.to_string(),
                            address: sym_ref.st_value as Addr,
                            size: sym_ref.st_size as usize,
                            sym_type: SymbolType::Function,
                            file_offset: 0,
                            obj_file_name: None,
                        });
                    }
                }
                Ok(found)
            }
            Err(_) => Ok(vec![]),
        }
    }

    pub(crate) fn find_address_regex(
        &self,
        pattern: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"))
        }


        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab()?;
        let () = cache.ensure_str2symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();
        // SANITY: The above `ensure_str2symtab` ensures we have
        //         `str2symtab` available.
        let str2symtab = cache.str2symtab.as_ref().unwrap();

        let re = Regex::new(pattern).unwrap();
        let mut syms = vec![];
        for (sname, sym_i) in str2symtab {
            if re.is_match(sname) {
                let sym_ref = &symtab.get(*sym_i).ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("index ({sym_i}) into ELF symbol table out of bounds"),
                    )
                })?;
                if sym_ref.st_shndx != SHN_UNDEF {
                    syms.push(SymbolInfo {
                        name: sname.to_string(),
                        address: sym_ref.st_value as Addr,
                        size: sym_ref.st_size as usize,
                        sym_type: SymbolType::Function,
                        file_offset: 0,
                        obj_file_name: None,
                    });
                }
            }
        }
        Ok(syms)
    }

    #[cfg(test)]
    fn get_symbol_name(&self, idx: usize) -> Result<&str, Error> {
        let mut cache = self.cache.borrow_mut();
        let sym = cache.symbol(idx)?;
        let name = cache.symbol_name(sym)?;
        Ok(name)
    }

    pub(crate) fn get_all_program_headers(&self) -> Result<&[Elf64_Phdr], Error> {
        let mut cache = self.cache.borrow_mut();
        let phdrs = cache.ensure_phdrs()?;
        Ok(phdrs)
    }

    #[cfg(test)]
    fn pick_symtab_addr(&self) -> (&str, Addr) {
        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab().unwrap();
        let symtab = cache.symtab.as_ref().unwrap();

        let mut idx = symtab.len() / 2;
        while symtab[idx].st_info & 0xf != STT_FUNC || symtab[idx].st_shndx == SHN_UNDEF {
            idx += 1;
        }
        let sym = &symtab[idx];
        let addr = sym.st_value;
        drop(cache);

        let sym_name = self.get_symbol_name(idx).unwrap();
        (sym_name, addr as Addr)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use test_log::test;


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

        let (sym_name, addr) = parser.pick_symtab_addr();

        let sym_r = parser.find_symbol(addr, STT_FUNC);
        assert!(sym_r.is_ok());
        let (sym_name_ret, addr_ret) = sym_r.unwrap();
        assert_eq!(addr_ret, addr);
        assert_eq!(sym_name_ret, sym_name);
    }

    #[test]
    fn test_elf64_find_address() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (sym_name, addr) = parser.pick_symtab_addr();

        println!("{sym_name}");
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        let addr_r = parser.find_address(sym_name, &opts).unwrap();
        assert_eq!(addr_r.len(), 1);
        assert!(addr_r.iter().any(|x| x.address == addr));
    }
}

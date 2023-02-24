use std::cell::RefCell;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom};
use std::mem;
#[cfg(test)]
use std::path::Path;

use memmap::Mmap;

use regex::Regex;

use crate::util::{extract_string, search_address_opt_key};
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


fn read_u8(mut file: &File, off: u64, size: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; size];

    file.seek(SeekFrom::Start(off))?;
    file.read_exact(buf.as_mut_slice())?;

    Ok(buf)
}

fn read_elf_header(mut file: &File) -> Result<Elf64_Ehdr, Error> {
    let mut buffer = [0u8; mem::size_of::<Elf64_Ehdr>()];
    let () = file.read_exact(&mut buffer)?;

    let pointer = buffer.as_ptr() as *const Elf64_Ehdr;
    // SAFETY: `buffer` is valid for reads and the `Elf64_Ehdr` object that we
    //         read is comprised only of members that are valid for any bit
    //         pattern.
    let elf_header = unsafe { pointer.read_unaligned() };

    Ok(elf_header)
}

fn read_elf_sections(file: &File, ehdr: &Elf64_Ehdr) -> Result<Vec<Elf64_Shdr>, Error> {
    const HDRSIZE: usize = mem::size_of::<Elf64_Shdr>();
    let off = ehdr.e_shoff as usize;
    let num = ehdr.e_shnum as usize;

    let mut buf = read_u8(file, off as u64, num * HDRSIZE)?;

    let shdrs: Vec<Elf64_Shdr> = unsafe {
        let shdrs_ptr = buf.as_mut_ptr() as *mut Elf64_Shdr;
        buf.leak();
        Vec::from_raw_parts(shdrs_ptr, num, num)
    };
    Ok(shdrs)
}

fn read_elf_program_headers(file: &File, ehdr: &Elf64_Ehdr) -> Result<Vec<Elf64_Phdr>, Error> {
    const HDRSIZE: usize = mem::size_of::<Elf64_Phdr>();
    let off = ehdr.e_phoff as usize;
    let num = ehdr.e_phnum as usize;

    let mut buf = read_u8(file, off as u64, num * HDRSIZE)?;

    let phdrs: Vec<Elf64_Phdr> = unsafe {
        let phdrs_ptr = buf.as_mut_ptr() as *mut Elf64_Phdr;
        buf.leak();
        Vec::from_raw_parts(phdrs_ptr, num, num)
    };
    Ok(phdrs)
}

fn read_elf_section_raw(file: &File, section: &Elf64_Shdr) -> Result<Vec<u8>, Error> {
    read_u8(file, section.sh_offset, section.sh_size as usize)
}

fn get_elf_section_name<'a>(sect: &Elf64_Shdr, strtab: &'a [u8]) -> Option<&'a str> {
    extract_string(strtab, sect.sh_name as usize)
}

#[derive(Debug, Default)]
struct Cache {
    ehdr: Option<Elf64_Ehdr>,
    shdrs: Option<Vec<Elf64_Shdr>>,
    shstrtab: Option<Vec<u8>>,
    phdrs: Option<Vec<Elf64_Phdr>>,
    symtab: Option<Vec<Elf64_Sym>>,        // in address order
    symtab_origin: Option<Vec<Elf64_Sym>>, // The copy in the same order as the file
    strtab: Option<Vec<u8>>,
    str2symtab: Option<Vec<(usize, usize)>>, // strtab offset to symtab in the dictionary order
    sect_cache: Vec<Option<Vec<u8>>>,
}

/// A parser for ELF64 files.
#[derive(Debug)]
pub struct ElfParser {
    /// The file representing the ELF object to be parsed.
    file: File,
    /// The memory mapped file.
    mmap: Mmap,
    /// A cache for relevant parts of the ELF file.
    cache: RefCell<Cache>,
}

impl ElfParser {
    pub fn open_file(file: File) -> Result<ElfParser, Error> {
        let mmap = unsafe { Mmap::map(&file) }?;
        let parser = ElfParser {
            file,
            mmap,
            cache: RefCell::new(Cache::default()),
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

    fn ensure_ehdr(&self) -> Result<(), Error> {
        let mut cache = self.cache.borrow_mut();

        if cache.ehdr.is_some() {
            return Ok(());
        }

        let ehdr = read_elf_header(&self.file)?;
        if !(ehdr.e_ident[0] == 0x7f
            && ehdr.e_ident[1] == 0x45
            && ehdr.e_ident[2] == 0x4c
            && ehdr.e_ident[3] == 0x46)
        {
            return Err(Error::new(ErrorKind::InvalidData, "e_ident is wrong"));
        }

        cache.ehdr = Some(ehdr);

        Ok(())
    }

    fn ensure_shdrs(&self) -> Result<(), Error> {
        self.ensure_ehdr()?;

        let mut cache = self.cache.borrow_mut();

        if cache.shdrs.is_some() {
            return Ok(());
        }

        let shdrs = read_elf_sections(&self.file, cache.ehdr.as_ref().unwrap())?;
        cache.sect_cache.resize(shdrs.len(), None);
        cache.shdrs = Some(shdrs);

        Ok(())
    }

    fn ensure_phdrs(&self) -> Result<(), Error> {
        self.ensure_ehdr()?;

        let mut cache = self.cache.borrow_mut();

        if cache.phdrs.is_some() {
            return Ok(());
        }

        let phdrs = read_elf_program_headers(&self.file, cache.ehdr.as_ref().unwrap())?;
        cache.phdrs = Some(phdrs);

        Ok(())
    }

    fn ensure_shstrtab(&self) -> Result<(), Error> {
        self.ensure_shdrs()?;

        let mut cache = self.cache.borrow_mut();

        if cache.shstrtab.is_some() {
            return Ok(());
        }

        let shstrndx = cache.ehdr.as_ref().unwrap().e_shstrndx;
        let shstrtab_sec = &cache.shdrs.as_ref().unwrap()[shstrndx as usize];
        let shstrtab = read_elf_section_raw(&self.file, shstrtab_sec)?;
        cache.shstrtab = Some(shstrtab);

        Ok(())
    }

    fn ensure_symtab(&self) -> Result<(), Error> {
        {
            let cache = self.cache.borrow();

            if cache.symtab.is_some() {
                return Ok(());
            }
        }

        let sect_idx = if let Ok(idx) = self.find_section(".symtab") {
            idx
        } else {
            self.find_section(".dynsym")?
        };
        let symtab_raw = self.read_section_raw(sect_idx)?;

        if symtab_raw.len() % mem::size_of::<Elf64_Sym>() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "size of the .symtab section does not match",
            ));
        }
        let cnt = symtab_raw.len() / mem::size_of::<Elf64_Sym>();
        let mut symtab: Vec<Elf64_Sym> = unsafe {
            let symtab_ptr = symtab_raw.as_ptr() as *mut Elf64_Sym;
            symtab_raw.leak();
            Vec::from_raw_parts(symtab_ptr, cnt, cnt)
        };
        let origin = symtab.clone();
        symtab.sort_by_key(|x| x.st_value);

        let mut cache = self.cache.borrow_mut();
        cache.symtab = Some(symtab);
        cache.symtab_origin = Some(origin);

        Ok(())
    }

    fn ensure_strtab(&self) -> Result<(), Error> {
        {
            let cache = self.cache.borrow();

            if cache.strtab.is_some() {
                return Ok(());
            }
        }

        let sect_idx = if let Ok(idx) = self.find_section(".strtab") {
            idx
        } else {
            self.find_section(".dynstr")?
        };
        let strtab = self.read_section_raw(sect_idx)?;

        let mut cache = self.cache.borrow_mut();
        cache.strtab = Some(strtab);

        Ok(())
    }

    fn ensure_str2symtab(&self) -> Result<(), Error> {
        self.ensure_symtab()?;
        self.ensure_strtab()?;

        let mut cache = self.cache.borrow_mut();
        if cache.str2symtab.is_some() {
            return Ok(());
        }

        // Build strtab offsets to symtab indices
        let strtab = cache.strtab.as_ref().unwrap();
        let symtab = cache.symtab.as_ref().unwrap();
        let mut str2symtab = Vec::<(usize, usize)>::with_capacity(symtab.len());
        for (sym_i, sym) in symtab.iter().enumerate() {
            let name_off = sym.st_name;
            str2symtab.push((name_off as usize, sym_i));
        }

        // Sort in the dictionary order
        str2symtab.sort_by_key(|&x| unsafe { CStr::from_ptr(strtab[x.0..].as_ptr().cast()) });

        cache.str2symtab = Some(str2symtab);

        Ok(())
    }

    pub fn get_elf_file_type(&self) -> Result<u16, Error> {
        self.ensure_ehdr()?;

        let cache = self.cache.borrow();

        Ok(cache.ehdr.as_ref().unwrap().e_type)
    }

    fn check_section_index(&self, sect_idx: usize) -> Result<(), Error> {
        let nsects = self.get_num_sections()?;

        if nsects <= sect_idx {
            return Err(Error::new(ErrorKind::InvalidInput, "the index is too big"));
        }
        Ok(())
    }

    /// Retrieve the data corresponding to the ELF section at index `idx`.
    pub fn section_data(&self, idx: usize) -> Result<&[u8], Error> {
        self.check_section_index(idx)?;
        self.ensure_shdrs()?;
        let cache = self.cache.borrow();
        let section = cache.shdrs.as_ref().unwrap()[idx];
        let offset = section.sh_offset as usize;
        let size = section.sh_size as usize;

        self.mmap
            .get(offset..offset + size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "ELF section data out of bounds"))
    }

    /// Read the raw data of the section of a given index.
    pub fn read_section_raw(&self, sect_idx: usize) -> Result<Vec<u8>, Error> {
        self.check_section_index(sect_idx)?;
        self.ensure_shdrs()?;

        let cache = self.cache.borrow();
        read_elf_section_raw(&self.file, &cache.shdrs.as_ref().unwrap()[sect_idx])
    }

    /// Read the raw data of the section of a given index.
    pub fn read_section_raw_cache(&self, sect_idx: usize) -> Result<&[u8], Error> {
        self.check_section_index(sect_idx)?;
        self.ensure_shdrs()?;

        let mut cache = self.cache.borrow_mut();
        if cache.sect_cache[sect_idx].is_none() {
            let buf = read_elf_section_raw(&self.file, &cache.shdrs.as_ref().unwrap()[sect_idx])?;
            cache.sect_cache[sect_idx] = Some(buf);
        }

        Ok(unsafe { mem::transmute(cache.sect_cache[sect_idx].as_ref().unwrap().as_slice()) })
    }

    /// Get the name of the section of a given index.
    pub fn get_section_name(&self, sect_idx: usize) -> Result<&str, Error> {
        self.check_section_index(sect_idx)?;

        self.ensure_shstrtab()?;

        let cache = self.cache.borrow();

        let sect = &cache.shdrs.as_ref().unwrap()[sect_idx];
        let name = get_elf_section_name(sect, unsafe {
            (*self.cache.as_ptr()).shstrtab.as_ref().unwrap()
        });
        if name.is_none() {
            return Err(Error::new(ErrorKind::InvalidData, "invalid section name"));
        }
        Ok(name.unwrap())
    }

    pub fn get_section_size(&self, sect_idx: usize) -> Result<usize, Error> {
        self.check_section_index(sect_idx)?;
        self.ensure_shdrs()?;

        let cache = self.cache.borrow();
        let sect = &cache.shdrs.as_ref().unwrap()[sect_idx];
        Ok(sect.sh_size as usize)
    }

    pub fn get_num_sections(&self) -> Result<usize, Error> {
        self.ensure_ehdr()?;
        let cache = self.cache.borrow();
        Ok(cache.ehdr.as_ref().unwrap().e_shnum as usize)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub fn find_section(&self, name: &str) -> Result<usize, Error> {
        let nsects = self.get_num_sections()?;
        for i in 0..nsects {
            if self.get_section_name(i)? == name {
                return Ok(i);
            }
        }
        Err(Error::new(
            ErrorKind::NotFound,
            format!("unable to find ELF section: {name}"),
        ))
    }

    pub fn find_symbol(&self, address: u64, st_type: u8) -> Result<(&str, u64), Error> {
        self.ensure_symtab()?;
        self.ensure_strtab()?;

        let cache = self.cache.borrow();
        let idx_r = search_address_opt_key(
            cache.symtab.as_ref().unwrap(),
            address,
            &|sym: &Elf64_Sym| {
                if sym.st_info & 0xf != st_type || sym.st_shndx == SHN_UNDEF {
                    None
                } else {
                    Some(sym.st_value)
                }
            },
        );
        if idx_r.is_none() {
            return Err(Error::new(
                ErrorKind::NotFound,
                "Does not found a symbol for the given address",
            ));
        }
        let idx = idx_r.unwrap();

        let sym = &cache.symtab.as_ref().unwrap()[idx];
        let sym_name = match extract_string(
            unsafe { (*self.cache.as_ptr()).strtab.as_ref().unwrap().as_slice() },
            sym.st_name as usize,
        ) {
            Some(sym_name) => sym_name,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid symbol name string/offset",
                ));
            }
        };
        Ok((sym_name, sym.st_value))
    }

    pub fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"));
        }

        self.ensure_str2symtab()?;

        let cache = self.cache.borrow();
        let str2symtab = cache.str2symtab.as_ref().unwrap();
        let strtab = cache.strtab.as_ref().unwrap();
        let r = str2symtab.binary_search_by_key(&name.to_string(), |&x| {
            String::from(
                unsafe { CStr::from_ptr(strtab[x.0..].as_ptr().cast()) }
                    .to_str()
                    .unwrap(),
            )
        });

        match r {
            Ok(str2sym_i) => {
                let mut idx = str2sym_i;
                while idx > 0 {
                    let name_seek = unsafe {
                        CStr::from_ptr(strtab[str2symtab[idx].0..].as_ptr().cast())
                            .to_str()
                            .unwrap()
                    };
                    if !name_seek.eq(name) {
                        idx += 1;
                        break;
                    }
                    idx -= 1;
                }

                let mut found = vec![];
                for idx in idx..str2symtab.len() {
                    let name_visit = unsafe {
                        CStr::from_ptr(strtab[str2symtab[idx].0..].as_ptr().cast())
                            .to_str()
                            .unwrap()
                    };
                    if !name_visit.eq(name) {
                        break;
                    }
                    let sym_i = str2symtab[idx].1;
                    let sym_ref = &cache.symtab.as_ref().unwrap()[sym_i];
                    if sym_ref.st_shndx != SHN_UNDEF {
                        found.push(SymbolInfo {
                            name: name.to_string(),
                            address: sym_ref.st_value,
                            size: sym_ref.st_size,
                            sym_type: SymbolType::Function,
                            ..Default::default()
                        });
                    }
                }
                Ok(found)
            }
            Err(_) => Ok(vec![]),
        }
    }

    pub fn find_address_regex(
        &self,
        pattern: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"));
        }

        self.ensure_str2symtab()?;

        let cache = self.cache.borrow();
        let str2symtab = cache.str2symtab.as_ref().unwrap();
        let strtab = cache.strtab.as_ref().unwrap();
        let re = Regex::new(pattern).unwrap();
        let mut syms = vec![];
        for (str_off, sym_i) in str2symtab {
            let sname = unsafe {
                CStr::from_ptr(strtab[*str_off..].as_ptr().cast())
                    .to_str()
                    .unwrap()
            };
            if re.is_match(sname) {
                let sym_ref = &cache.symtab.as_ref().unwrap()[*sym_i];
                if sym_ref.st_shndx != SHN_UNDEF {
                    syms.push(SymbolInfo {
                        name: sname.to_string(),
                        address: sym_ref.st_value,
                        size: sym_ref.st_size,
                        sym_type: SymbolType::Function,
                        ..Default::default()
                    });
                }
            }
        }
        Ok(syms)
    }

    #[cfg(test)]
    fn get_symbol(&self, idx: usize) -> Result<&Elf64_Sym, Error> {
        self.ensure_symtab()?;

        let cache = self.cache.as_ptr();
        Ok(unsafe { &(*cache).symtab.as_mut().unwrap()[idx] })
    }

    #[cfg(test)]
    fn get_symbol_name(&self, idx: usize) -> Result<&str, Error> {
        let sym = self.get_symbol(idx)?;

        let cache = self.cache.as_ptr();
        let sym_name = match extract_string(
            unsafe { (*cache).strtab.as_ref().unwrap().as_slice() },
            sym.st_name as usize,
        ) {
            Some(name) => name,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid symb name string/offset",
                ));
            }
        };

        Ok(sym_name)
    }

    pub fn get_all_program_headers(&self) -> Result<&[Elf64_Phdr], Error> {
        self.ensure_phdrs()?;

        let phdrs = unsafe {
            let cache = self.cache.as_ptr();
            let phdrs_ref = (*cache).phdrs.as_mut().unwrap();
            phdrs_ref
        };
        Ok(phdrs)
    }

    #[cfg(test)]
    fn pick_symtab_addr(&self) -> (&str, u64) {
        self.ensure_symtab().unwrap();
        self.ensure_strtab().unwrap();

        let cache = self.cache.borrow();
        let symtab = cache.symtab.as_ref().unwrap();
        let mut idx = symtab.len() / 2;
        while symtab[idx].st_info & 0xf != STT_FUNC || symtab[idx].st_shndx == SHN_UNDEF {
            idx += 1;
        }
        let sym = &symtab[idx];
        let addr = sym.st_value;
        drop(cache);

        let sym_name = self.get_symbol_name(idx).unwrap();
        (sym_name, addr)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_elf_header_sections() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let bin_file = File::open(bin_name).unwrap();
        let ehdr = read_elf_header(&bin_file);
        assert!(ehdr.is_ok());
        let ehdr = ehdr.unwrap();
        assert_eq!(
            ehdr.e_ident,
            [
                0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ]
        );
        assert_eq!(ehdr.e_version, 0x1);
        assert_eq!(ehdr.e_shentsize as usize, mem::size_of::<Elf64_Shdr>());

        let shdrs = read_elf_sections(&bin_file, &ehdr);
        assert!(shdrs.is_ok());
        let shdrs = shdrs.unwrap();
        let shstrndx = ehdr.e_shstrndx as usize;

        let shstrtab_sec = &shdrs[shstrndx];
        let shstrtab = read_elf_section_raw(&bin_file, shstrtab_sec);
        assert!(shstrtab.is_ok());
        let shstrtab = shstrtab.unwrap();

        let sec_name = get_elf_section_name(shstrtab_sec, &shstrtab);
        assert!(sec_name.is_some());
        assert_eq!(sec_name.unwrap(), ".shstrtab");
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

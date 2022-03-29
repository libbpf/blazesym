use std::mem;
use std::fs::{File};
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom};
use std::borrow::BorrowMut;

use std::cell::RefCell;

const EI_NIDENT: usize = 16;

type Elf64_Addr = u64;
type Elf64_Half = u16;
type Elf64_SHalf = u16;
type Elf64_Off = u64;
type Elf64_Sword = i32;
type Elf64_Word = u32;
type Elf64_Xword = u64;
type Elf64_Sxword = i64;

#[repr(C)]
struct Elf64_Ehdr {
    e_ident: [u8; EI_NIDENT],	/* ELF "magic number" */
    e_type: Elf64_Half,
    e_machine: Elf64_Half,
    e_version: Elf64_Word,
    e_entry: Elf64_Addr,	/* Entry point virtual address */
    e_phoff: Elf64_Off,		/* Program header table file offset */
    e_shoff: Elf64_Off,		/* Section header table file offset */
    e_flags: Elf64_Word,
    e_ehsize: Elf64_Half,
    e_phentsize: Elf64_Half,
    e_phnum: Elf64_Half,
    e_shentsize: Elf64_Half,
    e_shnum: Elf64_Half,
    e_shstrndx: Elf64_Half,
}

#[repr(C)]
struct Elf64_Phdr {
    p_type: Elf64_Word,
    p_flags: Elf64_Word,
    p_offset: Elf64_Off,	/* Segment file offset */
    p_vaddr: Elf64_Addr,	/* Segment virtual address */
    p_paddr: Elf64_Addr,	/* Segment physical address */
    p_filesz: Elf64_Xword,	/* Segment size in file */
    p_memsz: Elf64_Xword,	/* Segment size in memory */
    p_align: Elf64_Xword,	/* Segment alignment, file & memory */
}

#[repr(C)]
struct Elf64_Shdr {
    sh_name: Elf64_Word,	/* Section name, index in string tbl */
    sh_type: Elf64_Word,	/* Type of section */
    sh_flags: Elf64_Xword,	/* Miscellaneous section attributes */
    sh_addr: Elf64_Addr,	/* Section virtual addr at execution */
    sh_offset: Elf64_Off,	/* Section file offset */
    sh_size: Elf64_Xword,	/* Size of section in bytes */
    sh_link: Elf64_Word,	/* Index of another section */
    sh_info: Elf64_Word,	/* Additional section information */
    sh_addralign: Elf64_Xword,	/* Section alignment */
    sh_entsize: Elf64_Xword,	/* Entry size if section holds table */
}

#[repr(C)]
struct Elf64_Sym {
    st_name: Elf64_Word,	/* Symbol name, index in string tbl */
    st_info: u8,		/* Type and binding attributes */
    st_other: u8,		/* No defined meaning, 0 */
    st_shndx: Elf64_Half,	/* Associated section index */
    st_value: Elf64_Addr,	/* Value of the symbol */
    st_size: Elf64_Xword,	/* Associated symbol size */
}

#[repr(C)]
struct Elf64_Rel {
    r_offset: Elf64_Addr,	/* Location at which to apply the action */
    r_info: Elf64_Xword,	/* index and type of relocation */
}

#[repr(C)]
struct Elf64_Rela {
    r_offset: Elf64_Addr,	/* Location at which to apply the action */
    r_info: Elf64_Xword,	/* index and type of relocation */
    r_addend: Elf64_Sxword,	/* Constant addend used to compute value */
}

#[repr(C)]
union Elf64_Dyn_un{
    d_val: Elf64_Xword,
    d_ptr: Elf64_Addr,
}

#[repr(C)]
struct Elf64_Dyn {
    d_tag: Elf64_Sxword,	/* entry tag value */
    d_un: Elf64_Dyn_un,
}


fn read_u8(file: &mut File, off: u64, size: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; size];

    file.seek(SeekFrom::Start(off))?;
    file.read_exact(buf.as_mut_slice())?;

    Ok(buf)
}

fn read_elf_header(file: &mut File) -> Result<Elf64_Ehdr, Error> {
    const DSZ: usize = mem::size_of::<Elf64_Ehdr>();
    let mut buf = Box::new([0_u8; DSZ]);

    let buf_m: &mut [u8; DSZ] = buf.borrow_mut();
    file.read_exact(buf_m)?;

    let ehdr: Box<Elf64_Ehdr> = unsafe {
	// A complicated type casting hacking!!
	let ehdr_raw_ptr = (Box::leak(buf) as *mut u8) as *mut Elf64_Ehdr;
	Box::from_raw(ehdr_raw_ptr)
    };

    Ok(*ehdr)
}

fn read_elf_sections(file: &mut File, ehdr: &Elf64_Ehdr) -> Result<Vec<Elf64_Shdr>, Error> {
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

fn read_elf_section_raw(file: &mut File, section: &Elf64_Shdr) -> Result<Vec<u8>, Error> {
    read_u8(file, section.sh_offset as u64, section.sh_size as usize)
}

fn read_elf_section_seek(file: &mut File, section: &Elf64_Shdr) -> Result<(), Error> {
    file.seek(SeekFrom::Start(section.sh_offset as u64))?;
    Ok(())
}

fn read_elf_section_offset_seek(file: &mut File, section: &Elf64_Shdr, offset: usize) -> Result<(), Error> {
    if offset as u64 >= section.sh_size {
	return Err(Error::new(ErrorKind::InvalidInput, "the offset is too big"));
    }
    file.seek(SeekFrom::Start(section.sh_offset as u64 + offset as u64))?;
    Ok(())
}

fn extract_string(strtab: &[u8], off: usize) -> Option<String> {
    let mut end = off;

    if off >= strtab.len() {
	return None;
    }
    while strtab[end] != 0 {
	end += 1;
    }
    let blk = &strtab[off..end];
    let r = String::from_utf8(Vec::<u8>::from(blk));
    if r.is_err() {
	return None;
    }
    Some(r.unwrap())
}

fn get_elf_section_name(sect: &Elf64_Shdr, strtab: &[u8]) -> Option<String> {
    extract_string(strtab, sect.sh_name as usize)
}

struct Elf64ParserBack {
    ehdr: Option<Elf64_Ehdr>,
    shdrs: Option<Vec<Elf64_Shdr>>,
    shstrtab: Option<Vec<u8>>,
}

/// A parser against ELF64 format.
///
pub struct Elf64Parser {
    file: RefCell<File>,
    backobj: RefCell<Elf64ParserBack>,
}

impl Elf64Parser {
    pub fn open(filename: &str) -> Result<Elf64Parser, Error> {
	let file = File::open(filename)?;
	let parser = Elf64Parser {
	    file: RefCell::new(file),
	    backobj: RefCell::new(Elf64ParserBack {
		ehdr: None,
		shdrs: None,
		shstrtab: None,
	    }),
	};
	Ok(parser)
    }

    fn ensure_ehdr(&self) -> Result<(), Error> {
	let mut me = self.backobj.borrow_mut();

	if me.ehdr.is_some() {
	    return Ok(());
	}

	let ehdr = read_elf_header(&mut *self.file.borrow_mut())?;
	me.ehdr = Some(ehdr);

	Ok(())
    }

    fn ensure_shdrs(&self) -> Result<(), Error> {
	self.ensure_ehdr()?;

	let mut me = self.backobj.borrow_mut();

	if me.shdrs.is_some() {
	    return Ok(());
	}

	let shdrs = read_elf_sections(&mut *self.file.borrow_mut(), me.ehdr.as_ref().unwrap())?;
	me.shdrs = Some(shdrs);

	Ok(())
    }

    fn ensure_shstrtab(&self) -> Result<(), Error> {
	self.ensure_shdrs()?;

	let mut me = self.backobj.borrow_mut();

	if me.shstrtab.is_some() {
	    return Ok(());
	}

	let shstrndx = me.ehdr.as_ref().unwrap().e_shstrndx;
	let shstrtab_sec = &me.shdrs.as_ref().unwrap()[shstrndx as usize];
	let shstrtab = read_elf_section_raw(&mut *self.file.borrow_mut(), shstrtab_sec)?;
	me.shstrtab = Some(shstrtab);

	Ok(())
    }

    fn check_section_index(&self, sect_idx: usize) -> Result<(), Error> {
	let nsects = self.get_num_sections()?;

	if nsects <= sect_idx {
	    return Err(Error::new(ErrorKind::InvalidInput, "the index is too big"));
	}
	Ok(())
    }

    pub fn section_seek(&self, sect_idx: usize) -> Result<(), Error> {
	self.check_section_index(sect_idx)?;
	self.ensure_shdrs()?;
	let me = self.backobj.borrow();
	read_elf_section_seek(&mut *self.file.borrow_mut(), &me.shdrs.as_ref().unwrap()[sect_idx])
    }

    pub fn section_offset_seek(&self, sect_idx: usize, offset: usize) -> Result<(), Error> {
	self.check_section_index(sect_idx)?;
	self.ensure_shdrs()?;
	let me = self.backobj.borrow();
	read_elf_section_offset_seek(&mut *self.file.borrow_mut(), &me.shdrs.as_ref().unwrap()[sect_idx], offset)
    }

    /// Read the raw data of the section of a given index.
    pub fn read_section_raw(&self, sect_idx: usize) -> Result<Vec<u8>, Error> {
	self.check_section_index(sect_idx)?;
	self.ensure_shdrs()?;

	let me = self.backobj.borrow();
	read_elf_section_raw(&mut *self.file.borrow_mut(), &me.shdrs.as_ref().unwrap()[sect_idx])
    }

    /// Get the name of the section of a given index.
    pub fn get_section_name(&self, sect_idx: usize) -> Result<String, Error> {
	self.check_section_index(sect_idx)?;

	self.ensure_shstrtab()?;

	let me = self.backobj.borrow();

	let sect = &me.shdrs.as_ref().unwrap()[sect_idx];
	let name = get_elf_section_name(sect, me.shstrtab.as_ref().unwrap());
	if name.is_none() {
	    return Err(Error::new(ErrorKind::InvalidData, "invalid section name"));
	}
	Ok(name.unwrap())
    }

    pub fn get_section_size(&self, sect_idx: usize) -> Result<usize, Error> {
	self.check_section_index(sect_idx)?;
	self.ensure_shdrs()?;

	let me = self.backobj.borrow();
	let sect = &me.shdrs.as_ref().unwrap()[sect_idx];
	Ok(sect.sh_size as usize)
    }

    pub fn get_num_sections(&self) -> Result<usize, Error> {
	self.ensure_ehdr()?;
	let me = self.backobj.borrow();
	Ok(me.ehdr.as_ref().unwrap().e_shnum as usize)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub fn find_section(&self, name: &str) -> Result<usize, Error> {
	let nsects = self.get_num_sections()?;
	for i in 0..nsects {
	    if self.get_section_name(i).unwrap() == name {
		return Ok(i);
	    }
	}
	Err(Error::new(ErrorKind::NotFound, "Does not found the give section"))
    }

    /// Read raw data from the file at the current position.
    ///
    /// The caller can use section_seek() to move the current position
    /// of the backed file.  However, this function doesn't promise to
    /// not cross the boundary of the section.  The caller should take
    /// care about it.
    pub unsafe fn read_raw(&self, buf: &mut [u8]) -> Result<(), Error> {
	self.file.borrow_mut().read_exact(buf)?;
	Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_elf_header_sections() {
	let args: Vec<String> = env::args().collect();
	let bin_name = &args[0];

	let mut bin_file = File::open(bin_name).unwrap();
	let ehdr = read_elf_header(&mut bin_file);
	assert!(ehdr.is_ok());
	let ehdr = ehdr.unwrap();
	assert_eq!(ehdr.e_ident, [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
	assert_eq!(ehdr.e_version, 0x1);
	assert_eq!(ehdr.e_shentsize as usize, mem::size_of::<Elf64_Shdr>());

	let shdrs = read_elf_sections(&mut bin_file, &ehdr);
	assert!(shdrs.is_ok());
	let shdrs = shdrs.unwrap();
	let shstrndx = ehdr.e_shstrndx as usize;

	let shstrtab_sec = &shdrs[shstrndx];
	let shstrtab = read_elf_section_raw(&mut bin_file, shstrtab_sec);
	assert!(shstrtab.is_ok());
	let shstrtab = shstrtab.unwrap();

	let sec_name = get_elf_section_name(shstrtab_sec, &shstrtab);
	assert!(sec_name.is_some());
	assert_eq!(sec_name.unwrap(), ".shstrtab");
    }

    #[test]
    fn test_elf64_parser() {
	let args: Vec<String> = env::args().collect();
	let bin_name = &args[0];

	let parser = Elf64Parser::open(bin_name).unwrap();
	assert!(parser.find_section(".shstrtab").is_ok());
    }
}

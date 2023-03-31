use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;

use crate::Addr;
use crate::AddressLineInfo;
use crate::Error;
use crate::FindAddrOpts;
use crate::SymResolver;
use crate::SymbolInfo;

use super::cache::ElfBackend;
use super::types::ET_DYN;
use super::types::ET_EXEC;
use super::types::PF_X;
use super::types::PT_LOAD;
use super::types::STT_FUNC;
use super::ElfParser;

/// The symbol resolver for a single ELF file.
///
/// An ELF file may be loaded into an address space with a relocation.
/// The callers should provide the path of an ELF file and where it's
/// executable segment(s) is loaded.
///
/// For some ELF files, they are located at a specific address
/// determined during compile-time.  For these cases, just pass `0` as
/// it's loaded address.
pub struct ElfResolver {
    backend: ElfBackend,
    loaded_address: Addr,
    loaded_to_virt: Addr,
    foff_to_virt: usize,
    size: usize,
    file_name: PathBuf,
}

impl ElfResolver {
    pub(crate) fn new(
        file_name: &Path,
        loaded_address: Addr,
        backend: ElfBackend,
    ) -> Result<ElfResolver, Error> {
        let parser = match &backend {
            ElfBackend::Dwarf(dwarf) => dwarf.get_parser(),
            ElfBackend::Elf(parser) => parser,
        };
        let e_type = parser.get_elf_file_type()?;
        let phdrs = parser.get_all_program_headers()?;

        // Find the size of the block where the ELF file is/was
        // mapped.
        let mut max_addr = 0;
        let mut low_addr = 0xffffffffffffffff;
        let mut low_off = 0xffffffffffffffff;
        if e_type == ET_DYN || e_type == ET_EXEC {
            for phdr in phdrs {
                if phdr.p_type != PT_LOAD {
                    continue
                }
                if (phdr.p_flags & PF_X) != PF_X {
                    continue
                }
                let end_at = phdr.p_vaddr + phdr.p_memsz;
                if max_addr < end_at {
                    max_addr = end_at;
                }
                if phdr.p_vaddr < low_addr {
                    low_addr = phdr.p_vaddr;
                    low_off = phdr.p_offset;
                }
            }
        } else {
            return Err(Error::new(ErrorKind::InvalidData, "unknown e_type"))
        }

        let loaded_address = if e_type == ET_EXEC {
            low_addr as Addr
        } else {
            loaded_address
        };
        let loaded_to_virt = low_addr;
        let foff_to_virt = low_addr - low_off;
        let size = max_addr - low_addr;

        Ok(ElfResolver {
            backend,
            loaded_address,
            loaded_to_virt: loaded_to_virt as Addr,
            foff_to_virt: foff_to_virt as usize,
            size: size as usize,
            file_name: file_name.to_path_buf(),
        })
    }

    fn get_parser(&self) -> Option<&ElfParser> {
        match &self.backend {
            ElfBackend::Dwarf(dwarf) => Some(dwarf.get_parser()),
            ElfBackend::Elf(parser) => Some(parser),
        }
    }
}

impl SymResolver for ElfResolver {
    fn get_address_range(&self) -> (Addr, Addr) {
        (self.loaded_address, self.loaded_address + self.size)
    }

    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)> {
        let off = addr - self.loaded_address + self.loaded_to_virt;
        let parser = if let Some(parser) = self.get_parser() {
            parser
        } else {
            return vec![]
        };

        match parser.find_symbol(off, STT_FUNC) {
            Ok((name, start_addr)) => {
                vec![(name, start_addr - self.loaded_to_virt + self.loaded_address)]
            }
            Err(_) => vec![],
        }
    }

    fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        let mut addr_res = match &self.backend {
            ElfBackend::Dwarf(dwarf) => dwarf.find_address(name, opts),
            ElfBackend::Elf(parser) => parser.find_address(name, opts),
        }
        .ok()?;
        for x in &mut addr_res {
            x.address = x.address - self.loaded_to_virt + self.loaded_address;
        }
        Some(addr_res)
    }

    fn find_address_regex(&self, pattern: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        let syms = match &self.backend {
            ElfBackend::Dwarf(dwarf) => dwarf.find_address_regex(pattern, opts),
            ElfBackend::Elf(parser) => parser.find_address_regex(pattern, opts),
        };
        if syms.is_err() {
            return None
        }
        let mut syms = syms.unwrap();
        for sym in &mut syms {
            sym.address = sym.address - self.loaded_to_virt + self.loaded_address;
        }
        Some(syms)
    }

    fn find_line_info(&self, addr: Addr) -> Option<AddressLineInfo> {
        let off = addr - self.loaded_address + self.loaded_to_virt;
        if let ElfBackend::Dwarf(dwarf) = &self.backend {
            let (directory, file, line_no) = dwarf.find_line_as_ref(off)?;
            let mut path = String::from(directory);
            if !path.is_empty() && &path[(path.len() - 1)..] != "/" {
                path.push('/');
            }
            path.push_str(file);
            Some(AddressLineInfo {
                path,
                line_no,
                column: 0,
            })
        } else {
            None
        }
    }

    fn addr_file_off(&self, addr: Addr) -> Option<u64> {
        let offset = addr - self.loaded_address + self.loaded_to_virt - self.foff_to_virt;
        Some(offset as u64)
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }
}

impl Debug for ElfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.backend {
            ElfBackend::Dwarf(_) => write!(f, "DWARF {}", self.file_name.display()),
            ElfBackend::Elf(_) => write!(f, "ELF {}", self.file_name.display()),
        }
    }
}

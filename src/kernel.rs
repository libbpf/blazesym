use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::ops::Deref as _;
use std::path::Path;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::ksym::KSymResolver;
use crate::Addr;
use crate::AddressLineInfo;
use crate::FindAddrOpts;
use crate::SymResolver;
use crate::SymbolInfo;


pub(crate) struct KernelResolver {
    pub ksym_resolver: Option<Rc<KSymResolver>>,
    pub elf_resolver: Option<ElfResolver>,
}

impl KernelResolver {
    pub fn new(
        ksym_resolver: Option<Rc<KSymResolver>>,
        elf_resolver: Option<ElfResolver>,
    ) -> Result<KernelResolver> {
        if ksym_resolver.is_none() && elf_resolver.is_none() {
            return Err(Error::new(
                ErrorKind::NotFound,
                    "failed to create kernel resolver: neither ksym resolver nor kernel image ELF resolver are present",
            ))
        }

        Ok(KernelResolver {
            ksym_resolver,
            elf_resolver,
        })
    }
}

impl SymResolver for KernelResolver {
    fn get_address_range(&self) -> (Addr, Addr) {
        (0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)> {
        if let Some(ksym_resolver) = self.ksym_resolver.as_ref() {
            ksym_resolver.find_symbols(addr)
        } else {
            self.elf_resolver.as_ref().unwrap().find_symbols(addr)
        }
    }
    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }
    fn find_address_regex(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }
    fn find_line_info(&self, addr: Addr) -> Option<AddressLineInfo> {
        self.elf_resolver
            .as_ref()
            .and_then(|resolver| resolver.find_line_info(addr))
    }

    fn addr_file_off(&self, _addr: Addr) -> Option<u64> {
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        let ksym_resolver = self
            .ksym_resolver
            .as_ref()
            .map(|resolver| resolver.deref() as &dyn SymResolver);
        let elf_resolver = self
            .elf_resolver
            .as_ref()
            .map(|resolver| resolver as &dyn SymResolver);

        ksym_resolver
            .or(elf_resolver)
            .map(|resolver| resolver.get_obj_file_name())
            .unwrap_or_else(|| Path::new(""))
    }
}

impl Debug for KernelResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "KernelResolver {} {}",
            self.ksym_resolver
                .as_ref()
                .map(|resolver| resolver.get_obj_file_name().to_path_buf())
                .unwrap_or_default()
                .display(),
            self.elf_resolver
                .as_ref()
                .map(|resolver| resolver.get_obj_file_name().to_path_buf())
                .unwrap_or_default()
                .display(),
        )
    }
}

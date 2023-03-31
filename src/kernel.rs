use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::ksym::KSymResolver;
use crate::Addr;
use crate::AddressLineInfo;
use crate::CacheHolder;
use crate::FindAddrOpts;
use crate::SymResolver;
use crate::SymbolInfo;


pub(crate) struct KernelResolver {
    pub ksym_resolver: Option<Rc<KSymResolver>>,
    pub kernelresolver: Option<ElfResolver>,
    kernel_image: PathBuf,
}

impl KernelResolver {
    pub fn new(
        ksym_resolver: Option<Rc<KSymResolver>>,
        kernel_image: &Path,
        cache_holder: &CacheHolder,
    ) -> Result<KernelResolver> {
        let backend = cache_holder.get_elf_cache().find(kernel_image)?;
        let kernelresolver = ElfResolver::new(kernel_image, 0, backend);

        if ksym_resolver.is_none() && kernelresolver.is_err() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "failed to load {} and no ksym resolver is present",
                    kernel_image.display()
                ),
            ))
        }

        Ok(KernelResolver {
            ksym_resolver,
            kernelresolver: kernelresolver.ok(),
            kernel_image: kernel_image.to_path_buf(),
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
            self.kernelresolver.as_ref().unwrap().find_symbols(addr)
        }
    }
    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }
    fn find_address_regex(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }
    fn find_line_info(&self, addr: Addr) -> Option<AddressLineInfo> {
        self.kernelresolver
            .as_ref()
            .and_then(|resolver| resolver.find_line_info(addr))
    }

    fn addr_file_off(&self, _addr: Addr) -> Option<u64> {
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.kernel_image
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
            self.kernel_image.display()
        )
    }
}

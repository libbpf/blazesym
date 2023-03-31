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
    pub ksymresolver: Option<Rc<KSymResolver>>,
    pub kernelresolver: Option<ElfResolver>,
    kallsyms: PathBuf,
    kernel_image: PathBuf,
}

impl KernelResolver {
    pub fn new(
        kallsyms: &Path,
        kernel_image: &Path,
        cache_holder: &CacheHolder,
    ) -> Result<KernelResolver> {
        let ksymresolver = cache_holder.get_ksym_cache().get_resolver(kallsyms);
        let kernelresolver = ElfResolver::new(kernel_image, 0, cache_holder);

        if ksymresolver.is_err() && kernelresolver.is_err() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "can not load {} and {}",
                    kallsyms.display(),
                    kernel_image.display()
                ),
            ))
        }

        Ok(KernelResolver {
            ksymresolver: ksymresolver.ok(),
            kernelresolver: kernelresolver.ok(),
            kallsyms: kallsyms.to_path_buf(),
            kernel_image: kernel_image.to_path_buf(),
        })
    }
}

impl SymResolver for KernelResolver {
    fn get_address_range(&self) -> (Addr, Addr) {
        (0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)> {
        if self.ksymresolver.is_some() {
            self.ksymresolver.as_ref().unwrap().find_symbols(addr)
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
        self.kernelresolver.as_ref()?;
        self.kernelresolver.as_ref().unwrap().find_line_info(addr)
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
            self.kallsyms.display(),
            self.kernel_image.display()
        )
    }
}

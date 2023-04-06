use std::fmt::Debug;
use std::io::Result;
use std::path::Component;
use std::path::Path;

use crate::cfg;
use crate::elf::ElfCache;
use crate::elf::ElfResolver;
use crate::gsym::GsymResolver;
use crate::kernel::KernelResolver;
use crate::ksym::KSymCache;
use crate::ksym::KALLSYMS;
use crate::log;
use crate::maps;
use crate::maps::Pid;
use crate::util;
use crate::util::uname_release;
use crate::Addr;
use crate::AddressLineInfo;
use crate::FindAddrOpts;
use crate::SymbolInfo;
use crate::SymbolSrcCfg;


/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e.g., a symbol file.
pub(crate) trait SymResolver
where
    Self: Debug,
{
    /// Return the range that this resolver serves in an address space.
    fn get_address_range(&self) -> (Addr, Addr);
    /// Find the names and the start addresses of a symbol found for
    /// the given address.
    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)>;
    /// Find the address and size of a symbol name.
    fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the addresses and sizes of the symbols matching a given pattern.
    fn find_address_regex(&self, pattern: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: Addr) -> Option<AddressLineInfo>;
    /// Translate an address (virtual) in a process to the file offset
    /// in the object file.
    fn addr_file_off(&self, addr: Addr) -> Option<u64>;
    /// Get the file name of the shared object.
    fn get_obj_file_name(&self) -> &Path;
}


type ResolverList = Vec<((Addr, Addr), Box<dyn SymResolver>)>;


pub(crate) struct ResolverMap {
    pub resolvers: ResolverList,
}

impl ResolverMap {
    fn build_resolvers_proc_maps(
        pid: u32,
        resolvers: &mut ResolverList,
        elf_cache: &ElfCache,
    ) -> Result<()> {
        let pid = if pid == 0 { Pid::Slf } else { Pid::Pid(pid) };
        let entries = maps::parse(pid)?;

        for entry in entries.iter() {
            if entry.path.as_path().components().next() != Some(Component::RootDir) {
                continue
            }
            if (entry.mode & 0b1010) != 0b1010 {
                // r-x-
                continue
            }

            if let Ok(meta_data) = entry.path.metadata() {
                if !meta_data.is_file() {
                    // Not a regular file
                    continue
                }
            } else {
                continue
            }

            let backend = elf_cache.find(&entry.path)?;
            let resolver = ElfResolver::new(&entry.path, entry.loaded_address, backend)?;
            let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
        }

        Ok(())
    }

    fn create_elf_resolver(cfg: &cfg::Elf, elf_cache: &ElfCache) -> Result<ElfResolver> {
        let cfg::Elf {
            file_name,
            base_address,
        } = cfg;

        let backend = elf_cache.find(file_name)?;
        let resolver = ElfResolver::new(file_name, *base_address, backend)?;
        Ok(resolver)
    }

    fn create_kernel_resolver(
        cfg: &cfg::Kernel,
        ksym_cache: &KSymCache,
        elf_cache: &ElfCache,
    ) -> Result<KernelResolver> {
        let cfg::Kernel {
            kallsyms,
            kernel_image,
        } = cfg;

        let ksym_resolver = if let Some(kallsyms) = kallsyms {
            let ksym_resolver = ksym_cache.get_resolver(kallsyms)?;
            Some(ksym_resolver)
        } else {
            let kallsyms = Path::new(KALLSYMS);
            let result = ksym_cache.get_resolver(kallsyms);
            match result {
                Ok(resolver) => Some(resolver),
                Err(err) => {
                    log::warn!(
                        "failed to load kallsyms from {}: {err}; ignoring...",
                        kallsyms.display()
                    );
                    None
                }
            }
        };

        let elf_resolver = if let Some(image) = kernel_image {
            let backend = elf_cache.find(image)?;
            let elf_resolver = ElfResolver::new(image, 0, backend)?;
            Some(elf_resolver)
        } else {
            let release = uname_release()?.to_str().unwrap().to_string();
            let basename = "vmlinux-";
            let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
            let kernel_image = dirs.iter().find_map(|dir| {
                let path = dir.join(format!("{basename}{release}"));
                path.exists().then_some(path)
            });

            if let Some(image) = kernel_image {
                let result = elf_cache.find(&image);
                match result {
                    Ok(backend) => {
                        let result = ElfResolver::new(&image, 0, backend);
                        match result {
                            Ok(resolver) => Some(resolver),
                            Err(err) => {
                                log::warn!("failed to create ELF resolver for kernel image {}: {err}; ignoring...", image.display());
                                None
                            }
                        }
                    }
                    Err(err) => {
                        log::warn!(
                            "failed to load kernel image {}: {err}; ignoring...",
                            image.display()
                        );
                        None
                    }
                }
            } else {
                None
            }
        };

        let resolver = KernelResolver::new(ksym_resolver, elf_resolver)?;
        Ok(resolver)
    }

    pub fn new(
        sym_srcs: &[SymbolSrcCfg],
        ksym_cache: &KSymCache,
        elf_cache: &ElfCache,
    ) -> Result<ResolverMap> {
        let mut resolvers = ResolverList::new();
        for cfg in sym_srcs {
            match cfg {
                SymbolSrcCfg::Elf(elf) => {
                    let resolver = Self::create_elf_resolver(elf, elf_cache)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Kernel(kernel) => {
                    let resolver = Self::create_kernel_resolver(kernel, ksym_cache, elf_cache)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Process(cfg::Process { pid }) => {
                    let pid = if let Some(p) = pid { *p } else { 0 };
                    let () = Self::build_resolvers_proc_maps(pid, &mut resolvers, elf_cache)?;
                }
                SymbolSrcCfg::Gsym(cfg::Gsym {
                    file_name,
                    base_address,
                }) => {
                    let resolver = GsymResolver::new(file_name.clone(), *base_address)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
            }
        }
        resolvers.sort_by_key(|x| x.0 .0); // sorted by the loaded addresses

        Ok(ResolverMap { resolvers })
    }

    pub fn find_resolver(&self, address: Addr) -> Option<&dyn SymResolver> {
        let idx = util::find_match_or_lower_bound_by(&self.resolvers, address, |x| x.0 .0)?;
        let (loaded_begin, loaded_end) = self.resolvers[idx].0;
        if loaded_begin != loaded_end && address >= loaded_end {
            // `begin == end` means this ELF file may have only
            // symbols and debug information.  For this case, we
            // always use this resolver if the given address is just
            // above its loaded address.
            None
        } else {
            Some(self.resolvers[idx].1.as_ref())
        }
    }
}

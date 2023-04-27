use std::fmt::Debug;
use std::io::Result;
use std::path::Path;

use crate::cfg;
use crate::elf::ElfCache;
use crate::elf::ElfResolver;
use crate::ksym::KSymCache;
use crate::symbolize::AddrLineInfo;
use crate::Addr;
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
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: Addr) -> Option<AddrLineInfo>;
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
    fn create_elf_resolver(cfg: &cfg::Elf, elf_cache: &ElfCache) -> Result<ElfResolver> {
        let cfg::Elf {
            file_name,
            base_address,
        } = cfg;

        let backend = elf_cache.find(file_name)?;
        let resolver = ElfResolver::new(file_name, *base_address, backend)?;
        Ok(resolver)
    }

    pub fn new(
        sym_srcs: &[&SymbolSrcCfg],
        _ksym_cache: &KSymCache,
        elf_cache: &ElfCache,
    ) -> Result<ResolverMap> {
        let mut resolvers = ResolverList::new();
        for cfg in sym_srcs {
            match cfg {
                SymbolSrcCfg::Elf(elf) => {
                    let resolver = Self::create_elf_resolver(elf, elf_cache)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Kernel(..) => {
                    unreachable!()
                }
                SymbolSrcCfg::Process(..) => {
                    unreachable!()
                }
                SymbolSrcCfg::Gsym(..) => {
                    unreachable!()
                }
            }
        }
        resolvers.sort_by_key(|x| x.0 .0); // sorted by the loaded addresses

        Ok(ResolverMap { resolvers })
    }
}

use std::fmt::Debug;
use std::io::Result;
use std::path::Path;

use crate::elf::ElfCache;
use crate::elf::ElfResolver;
use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::ksym::KSymCache;
use crate::symbolize;
use crate::symbolize::AddrLineInfo;
use crate::symbolize::Source;
use crate::Addr;


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
    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymInfo>>;
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
    fn create_elf_resolver(src: &symbolize::Elf, elf_cache: &ElfCache) -> Result<ElfResolver> {
        let symbolize::Elf {
            path,
            base_address,
            _non_exhaustive: (),
        } = src;

        let backend = elf_cache.find(path)?;
        let resolver = ElfResolver::with_backend(path, *base_address, backend)?;
        Ok(resolver)
    }

    pub fn new(
        sym_srcs: &[&Source],
        _ksym_cache: &KSymCache,
        elf_cache: &ElfCache,
    ) -> Result<ResolverMap> {
        let mut resolvers = ResolverList::new();
        for src in sym_srcs {
            match src {
                Source::Elf(elf) => {
                    let resolver = Self::create_elf_resolver(elf, elf_cache)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                Source::Kernel(..) => {
                    unreachable!()
                }
                Source::Process(..) => {
                    unreachable!()
                }
                Source::Gsym(..) => {
                    unreachable!()
                }
            }
        }
        resolvers.sort_by_key(|x| x.0 .0); // sorted by the loaded addresses

        Ok(ResolverMap { resolvers })
    }
}

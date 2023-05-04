use std::fmt::Debug;
use std::io::Result;
use std::path::Path;
use std::path::PathBuf;

use crate::elf::ElfCache;
use crate::elf::ElfResolver;
use crate::gsym::GsymResolver;
use crate::inspect::FindAddrOpts;
use crate::inspect::SymbolInfo;
use crate::inspect::SymbolType;
use crate::kernel::KernelResolver;
use crate::ksym::KSymCache;
use crate::ksym::KALLSYMS;
use crate::log;
use crate::normalize::Binary;
use crate::normalize::NormalizedUserAddrs;
use crate::normalize::Normalizer;
use crate::normalize::UserAddrMeta;
use crate::resolver::ResolverMap;
use crate::util::uname_release;
use crate::Addr;
use crate::Pid;
use crate::SymResolver;

use super::source::Elf;
use super::source::Gsym;
use super::source::Kernel;
use super::source::Process;
use super::source::Source;


/// The result of symbolization by Symbolizer.
///
/// [`Symbolizer::symbolize()`] returns a list of lists of
/// `SymbolizedResult`.  It appears as `[[SymbolizedResult {...},
/// SymbolizedResult {...}, ...], [SymbolizedResult {...}, ...],
/// ...]`.  At the first level, each entry is a list of
/// `SymbolizedResult`.  [`Symbolizer::symbolize()`] can return
/// multiple results of an address due to compiler optimizations.
#[derive(Clone, Debug)]
pub struct SymbolizedResult {
    /// The symbol name that an address may belong to.
    pub symbol: String,
    /// The address where the symbol is located within the process.
    ///
    /// The address is in the target process, not the offset from the
    /// shared object file.
    pub addr: Addr,
    /// The source path that defines the symbol.
    pub path: PathBuf,
    /// The line number of the symbolized instruction in the source code.
    ///
    /// This is the line number of the instruction of the address being
    /// symbolized, not the line number that defines the symbol
    /// (function).
    pub line: usize,
    pub column: usize,
}


/// Switches in the features of Symbolizer.
///
/// Passing variants of this `enum` to [`Symbolizer::with_opts`] will enable
/// (true) or disable (false) respective features of a symbolizer.
#[derive(Debug)]
pub enum SymbolizerFeature {
    /// Switch on or off the feature of returning file names and line numbers of addresses.
    ///
    /// By default, it is true.  However, if it is false,
    /// the symbolizer will not return the line number information.
    LineNumberInfo(bool), // default is true.
    /// Switch on or off the feature of parsing symbols (subprogram) from DWARF.
    ///
    /// By default, it is false. BlazeSym parses symbols from DWARF
    /// only if the user of BlazeSym enables it.
    DebugInfoSymbols(bool),
}


/// Symbolizer provides an interface to symbolize addresses.
#[derive(Debug)]
pub struct Symbolizer {
    ksym_cache: KSymCache,
    elf_cache: ElfCache,
    line_number_info: bool,
}

impl Symbolizer {
    /// Create a new [`Symbolizer`].
    pub fn new() -> Self {
        let ksym_cache = KSymCache::new();

        let line_number_info = true;
        let debug_info_symbols = false;
        let elf_cache = ElfCache::new(line_number_info, debug_info_symbols);

        Self {
            ksym_cache,
            elf_cache,
            line_number_info,
        }
    }

    /// Create a new [`Symbolizer`] with the provided set of features.
    ///
    /// This constructor works like [`Symbolizer::new`] except it receives a
    /// list of [`SymbolizerFeature`] to turn on or off some features.
    pub fn with_opts(features: &[SymbolizerFeature]) -> Symbolizer {
        let mut line_number_info = true;
        let mut debug_info_symbols = false;

        for feature in features {
            match feature {
                SymbolizerFeature::LineNumberInfo(enabled) => {
                    line_number_info = *enabled;
                }
                SymbolizerFeature::DebugInfoSymbols(enabled) => {
                    debug_info_symbols = *enabled;
                }
            }
        }

        let ksym_cache = KSymCache::new();
        let elf_cache = ElfCache::new(line_number_info, debug_info_symbols);

        Self {
            ksym_cache,
            elf_cache,
            line_number_info,
        }
    }

    /// Find the addresses of a list of symbol names.
    ///
    /// Find the addresses of a list of symbol names using the provided
    /// configuration.
    pub fn find_addrs(&self, src: &Source, names: &[&str]) -> Result<Vec<Vec<SymbolInfo>>> {
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };

        let resolver_map = ResolverMap::new(&[src], &self.ksym_cache, &self.elf_cache)?;
        let mut syms_list = vec![];
        for name in names {
            let mut found = vec![];
            for (_, resolver) in &resolver_map.resolvers {
                if let Some(mut syms) = resolver.find_addr(name, &opts) {
                    for sym in &mut syms {
                        if opts.offset_in_file {
                            if let Some(off) = resolver.addr_file_off(sym.address) {
                                sym.file_offset = off;
                            }
                        }
                        if opts.obj_file_name {
                            sym.obj_file_name = Some(resolver.get_obj_file_name().to_path_buf());
                        }
                    }
                    found.append(&mut syms);
                }
            }
            syms_list.push(found);
        }
        Ok(syms_list)
    }

    /// Symbolize an address using the provided [`SymResolver`].
    fn symbolize_with_resolver(
        &self,
        addr: Addr,
        resolver: &dyn SymResolver,
    ) -> Vec<SymbolizedResult> {
        let res_syms = resolver.find_symbols(addr);
        let linfo = if self.line_number_info {
            resolver.find_line_info(addr)
        } else {
            None
        };
        if res_syms.is_empty() {
            if let Some(linfo) = linfo {
                vec![SymbolizedResult {
                    symbol: "".to_string(),
                    addr: 0,
                    path: linfo.path,
                    line: linfo.line,
                    column: linfo.column,
                }]
            } else {
                vec![]
            }
        } else {
            let mut results = vec![];
            for sym in res_syms {
                if let Some(ref linfo) = linfo {
                    let (sym, start) = sym;
                    results.push(SymbolizedResult {
                        symbol: String::from(sym),
                        addr: start,
                        path: linfo.path.clone(),
                        line: linfo.line,
                        column: linfo.column,
                    });
                } else {
                    let (sym, start) = sym;
                    results.push(SymbolizedResult {
                        symbol: String::from(sym),
                        addr: start,
                        path: PathBuf::new(),
                        line: 0,
                        column: 0,
                    });
                }
            }
            results
        }
    }

    /// Symbolize a list of addresses using the provided [`SymResolver`].
    fn symbolize_addrs(
        &self,
        addrs: &[Addr],
        resolver: &dyn SymResolver,
    ) -> Vec<Vec<SymbolizedResult>> {
        addrs
            .iter()
            .map(|addr| self.symbolize_with_resolver(*addr, resolver))
            .collect()
    }

    fn resolve_addr_in_binary(&self, addr: Addr, path: &Path) -> Result<Vec<SymbolizedResult>> {
        let backend = self.elf_cache.find(path)?;
        let resolver = ElfResolver::with_backend(path, 0, backend)?;
        let symbols = self.symbolize_with_resolver(addr, &resolver);
        Ok(symbols)
    }

    /// Symbolize the given list of user space addresses in the provided
    /// process.
    fn symbolize_user_addrs(&self, addrs: &[Addr], pid: Pid) -> Result<Vec<Vec<SymbolizedResult>>> {
        // TODO: We don't really *need to* use the
        //       `normalize_user_addrs` API here, which allocates a
        //       bunch etc. Rather, we could use internal APIs to only
        //       process necessary bits of proc maps as we go and while
        //       we have addresses to symbolize left.
        let normalizer = Normalizer::new();
        let normalized = normalizer.normalize_user_addrs(addrs, pid)?;

        let NormalizedUserAddrs {
            addrs: norm_addrs,
            meta: metas,
        } = normalized;

        let symbols = norm_addrs.into_iter().try_fold(
            Vec::with_capacity(addrs.len()),
            |mut all_symbols, (addr, meta_idx)| {
                let meta = &metas[meta_idx];

                match meta {
                    UserAddrMeta::Binary(Binary { path, .. }) => {
                        let symbols = self.resolve_addr_in_binary(addr, path)?;
                        all_symbols.push(symbols);
                    }
                    UserAddrMeta::Unknown(_unknown) => all_symbols.push(Vec::new()),
                }

                Result::Ok(all_symbols)
            },
        )?;

        Ok(symbols)
    }

    fn symbolize_kernel_addrs(
        &self,
        addrs: &[Addr],
        src: &Kernel,
    ) -> Result<Vec<Vec<SymbolizedResult>>> {
        let Kernel {
            kallsyms,
            kernel_image,
            _non_exhaustive: (),
        } = src;

        let ksym_resolver = if let Some(kallsyms) = kallsyms {
            let ksym_resolver = self.ksym_cache.get_resolver(kallsyms)?;
            Some(ksym_resolver)
        } else {
            let kallsyms = Path::new(KALLSYMS);
            let result = self.ksym_cache.get_resolver(kallsyms);
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
            let backend = self.elf_cache.find(image)?;
            let elf_resolver = ElfResolver::with_backend(image, 0, backend)?;
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
                let result = self.elf_cache.find(&image);
                match result {
                    Ok(backend) => {
                        let result = ElfResolver::with_backend(&image, 0, backend);
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
        let symbols = self.symbolize_addrs(addrs, &resolver);
        Ok(symbols)
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses according to the configuration
    /// provided via `src`.
    pub fn symbolize(&self, src: &Source, addrs: &[Addr]) -> Result<Vec<Vec<SymbolizedResult>>> {
        match src {
            Source::Elf(Elf {
                path,
                base_address,
                _non_exhaustive: (),
            }) => {
                let backend = self.elf_cache.find(path)?;
                let resolver = ElfResolver::with_backend(path, *base_address, backend)?;
                let symbols = self.symbolize_addrs(addrs, &resolver);
                Ok(symbols)
            }
            Source::Kernel(kernel) => self.symbolize_kernel_addrs(addrs, kernel),
            Source::Process(Process {
                pid,
                _non_exhaustive: (),
            }) => self.symbolize_user_addrs(addrs, *pid),
            Source::Gsym(Gsym {
                path,
                base_address,
                _non_exhaustive: (),
            }) => {
                let resolver = GsymResolver::new(path.clone(), *base_address)?;
                let symbols = self.symbolize_addrs(addrs, &resolver);
                Ok(symbols)
            }
        }
    }
}

impl Default for Symbolizer {
    fn default() -> Self {
        Self::new()
    }
}

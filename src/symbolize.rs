use std::fmt::Debug;
use std::io::Result;
use std::path::Path;
use std::path::PathBuf;

use crate::elf::ElfCache;
use crate::elf::ElfResolver;
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
use crate::FindAddrOpts;
use crate::Pid;
use crate::SymResolver;
use crate::SymbolInfo;
use crate::SymbolType;


pub struct AddrLineInfo {
    pub path: PathBuf,
    pub line_no: usize,
    pub column: usize,
}


pub mod cfg {
    use std::path::PathBuf;

    use crate::Addr;
    use crate::Pid;
    use crate::SymbolSrcCfg;

    #[cfg(doc)]
    use super::BlazeSymbolizer;


    /// A single ELF file.
    #[derive(Clone, Debug)]
    pub struct Elf {
        /// The name of ELF file.
        ///
        /// It can be an executable or shared object.
        /// For example, passing `"/bin/sh"` will load symbols and debug information from `sh`.
        /// Whereas passing `"/lib/libc.so.xxx"` will load symbols and debug information from the libc.
        pub file_name: PathBuf,
        /// The address where the executable segment loaded.
        ///
        /// The address in the process should be the executable segment's
        /// first byte.  For example, in `/proc/<pid>/maps`.
        ///
        /// ```text
        ///     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        ///     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        ///     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        ///     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        /// ```
        ///
        /// It reveals that the executable segment of libc-2.28.so was
        /// loaded at 0x7fe1b2dc4000.  This base address is used to
        /// translate an address in the segment to the corresponding
        /// address in the ELF file.
        ///
        /// A loader would load an executable segment with the permission of
        /// `x`.  For example, the first block is with the permission of
        /// `r-xp`.
        pub base_address: Addr,
    }

    impl From<Elf> for SymbolSrcCfg {
        fn from(elf: Elf) -> Self {
            SymbolSrcCfg::Elf(elf)
        }
    }


    /// Linux Kernel's binary image and a copy of /proc/kallsyms
    #[derive(Clone, Debug)]
    pub struct Kernel {
        /// The path of a kallsyms copy.
        ///
        /// For the running kernel on the device, it can be
        /// "/proc/kallsyms".  However, you can make a copy for later.
        /// In that situation, you should give the path of the
        /// copy.  Passing `None`, by default, will be
        /// `"/proc/kallsyms"`.
        pub kallsyms: Option<PathBuf>,
        /// The path of a kernel image.
        ///
        /// This should be the path of a kernel image.  For example,
        /// `"/boot/vmlinux-xxxx"`.  A `None` value will find the
        /// kernel image of the running kernel in `"/boot/"` or
        /// `"/usr/lib/debug/boot/"`.
        pub kernel_image: Option<PathBuf>,
    }

    impl From<Kernel> for SymbolSrcCfg {
        fn from(kernel: Kernel) -> Self {
            SymbolSrcCfg::Kernel(kernel)
        }
    }


    /// Configuration for process based address symbolization.
    ///
    /// The corresponding addresses supplied to
    /// [`BlazeSymbolizer::symbolize`] are expected to be absolute
    /// addresses as valid within the process identified by the
    /// [`pid`][Process::pid] member.
    #[derive(Clone, Debug)]
    pub struct Process {
        pub pid: Pid,
    }

    impl From<Process> for SymbolSrcCfg {
        fn from(process: Process) -> Self {
            SymbolSrcCfg::Process(process)
        }
    }


    /// A gsym file.
    #[derive(Clone, Debug)]
    pub struct Gsym {
        /// The path to the gsym file.
        pub file_name: PathBuf,
        /// The base address.
        pub base_address: Addr,
    }

    impl From<Gsym> for SymbolSrcCfg {
        fn from(gsym: Gsym) -> Self {
            SymbolSrcCfg::Gsym(gsym)
        }
    }
}

/// The description of a source of symbols and debug information.
///
/// The source of symbols and debug information can be an ELF file, kernel
/// image, or process.
#[derive(Clone, Debug)]
pub enum SymbolSrcCfg {
    /// A single ELF file
    Elf(cfg::Elf),
    /// Information about the Linux kernel.
    Kernel(cfg::Kernel),
    /// Information about a process.
    Process(cfg::Process),
    /// A gsym file.
    Gsym(cfg::Gsym),
}

/// The result of symbolization by BlazeSymbolizer.
///
/// [`BlazeSymbolizer::symbolize()`] returns a list of lists of
/// `SymbolizedResult`.  It appears as `[[SymbolizedResult {...},
/// SymbolizedResult {...}, ...], [SymbolizedResult {...}, ...],
/// ...]`.  At the first level, each entry is a list of
/// `SymbolizedResult`.  [`BlazeSymbolizer::symbolize()`] can return
/// multiple results of an address due to compiler optimizations.
#[derive(Clone, Debug)]
pub struct SymbolizedResult {
    /// The symbol name that an address may belong to.
    pub symbol: String,
    /// The address where the symbol is located within the process.
    ///
    /// The address is in the target process, not the offset from the
    /// shared object file.
    pub start_address: Addr,
    /// The source path that defines the symbol.
    pub path: PathBuf,
    /// The line number of the symbolized instruction in the source code.
    ///
    /// This is the line number of the instruction of the address being
    /// symbolized, not the line number that defines the symbol
    /// (function).
    pub line_no: usize,
    pub column: usize,
}


/// Switches in the features of BlazeSymbolizer.
///
/// Passing variants of this `enum` to [`BlazeSymbolizer::new_opt()`]
/// will enable (true) or disable (false) respective features
/// of a symbolizer.
#[derive(Debug)]
pub enum SymbolizerFeature {
    /// Switch on or off the feature of returning file names and line numbers of addresses.
    ///
    /// By default, it is true.  However, if it is false,
    /// the symbolizer will not return the line number information.
    LineNumberInfo(bool), // default is true.
    /// Switch on or off the feature of parsing symbols (subprogram) from DWARF.
    ///
    /// By default, it is false.  BlazeSym parses symbols from DWARF
    /// only if the user of BlazeSym enables it.
    DebugInfoSymbols(bool),
}

/// Switches and settings of features to modify the way looking up addresses of
/// symbols or the returned information.
#[derive(Debug)]
pub enum FindAddrFeature {
    /// Return the offset in the file.
    ///
    /// The offset will be returned as the value of `SymbolInfo::file_offset`.
    /// (Off by default)
    OffsetInFile(bool),
    /// Return the file name of the shared object.
    ///
    /// The name of the executable or object file will be returned as
    /// the value of `SymbolInfo::obj_file_name`.
    /// (Off by default)
    ObjFileName(bool),
    /// Return symbols having the given type.
    ///
    /// With `SymbolType::Function`, BlazeSym will return only the
    /// symbols that are functions.  With `SymbolType::Variable`,
    /// BlazeSym will return only the symbols that are variables.
    /// With `SymbolType::Unknown`, BlazeSym will return symbols of
    /// any type.
    SymbolType(SymbolType),
    /// Return symbols from the compile unit (source) of the given name.
    CommpileUnit(String),
}

/// BlazeSymbolizer provides an interface to symbolize addresses with
/// a list of symbol sources.
///
/// Users should present BlazeSymbolizer with a list of symbol sources
/// (`SymbolSrcCfg`); for example, an ELF file and its base address
/// (`SymbolSrcCfg::Elf`), or a Linux kernel image and a copy of its
/// kallsyms (`SymbolSrcCfg::Kernel`).  Additionally, BlazeSymbolizer
/// uses information from these sources to symbolize addresses.
#[derive(Debug)]
pub struct BlazeSymbolizer {
    ksym_cache: KSymCache,
    elf_cache: ElfCache,
    line_number_info: bool,
}

impl BlazeSymbolizer {
    /// Create and return an instance of BlazeSymbolizer.
    pub fn new() -> Result<BlazeSymbolizer> {
        let ksym_cache = KSymCache::new();

        let line_number_info = true;
        let debug_info_symbols = false;
        let elf_cache = ElfCache::new(line_number_info, debug_info_symbols);

        Ok(BlazeSymbolizer {
            ksym_cache,
            elf_cache,
            line_number_info,
        })
    }

    /// Create and return an instance of BlazeSymbolizer.
    ///
    /// `new_opt()` works like [`BlazeSymbolizer::new()`] except it receives a list of
    /// [`SymbolizerFeature`] to turn on or off some features.
    pub fn new_opt(features: &[SymbolizerFeature]) -> Result<BlazeSymbolizer> {
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

        Ok(BlazeSymbolizer {
            ksym_cache,
            elf_cache,
            line_number_info,
        })
    }

    fn find_addr_features_context(features: &[FindAddrFeature]) -> FindAddrOpts {
        let mut opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        for f in features {
            match f {
                FindAddrFeature::OffsetInFile(enable) => {
                    opts.offset_in_file = *enable;
                }
                FindAddrFeature::ObjFileName(enable) => {
                    opts.obj_file_name = *enable;
                }
                FindAddrFeature::SymbolType(sym_type) => {
                    opts.sym_type = *sym_type;
                }
                _ => {
                    todo!();
                }
            }
        }
        opts
    }

    /// Find the addresses of the symbols matching a pattern.
    ///
    /// Find the addresses of the symbols matching a pattern from the sources
    /// of symbols and debug info described by `sym_srcs`.
    /// `find_address_regex_opt()` works just like `find_address_regex()` with
    /// additional controls on features.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `pattern` - A regex pattern.
    /// * `features` - a list of `FindAddrFeature` to enable, disable, or specify parameters.
    pub fn find_address_regex_opt(
        &self,
        cfg: &SymbolSrcCfg,
        pattern: &str,
        features: &[FindAddrFeature],
    ) -> Option<Vec<SymbolInfo>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = match ResolverMap::new(&[cfg], &self.ksym_cache, &self.elf_cache) {
            Ok(map) => map,
            _ => return None,
        };
        let mut syms = vec![];
        for (_, resolver) in &resolver_map.resolvers {
            for mut sym in resolver
                .find_address_regex(pattern, &ctx)
                .unwrap_or_default()
            {
                if ctx.offset_in_file {
                    if let Some(off) = resolver.addr_file_off(sym.address) {
                        sym.file_offset = off;
                    }
                }
                if ctx.obj_file_name {
                    sym.obj_file_name = Some(resolver.get_obj_file_name().to_path_buf());
                }
                syms.push(sym);
            }
        }
        Some(syms)
    }

    /// Find the addresses of the symbols matching a pattern.
    ///
    /// Find the addresses of the symbols matching a pattern from the sources
    /// of symbols and debug info described by `sym_srcs`.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `pattern` - A regex pattern.
    pub fn find_address_regex(&self, cfg: &SymbolSrcCfg, pattern: &str) -> Option<Vec<SymbolInfo>> {
        self.find_address_regex_opt(cfg, pattern, &[])
    }

    /// Find the addresses of a list of symbol names.
    ///
    /// Find the addresses of a list of symbol names from the sources
    /// of symbols and debug info described by `sym_srcs`.
    /// `find_addresses_opt()` works just like `find_addresses()` with
    /// additional controls on features.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `names` - A list of symbol names.
    /// * `features` - a list of `FindAddrFeature` to enable, disable, or specify parameters.
    pub fn find_addresses_opt(
        &self,
        cfg: &SymbolSrcCfg,
        names: &[&str],
        features: &[FindAddrFeature],
    ) -> Result<Vec<Vec<SymbolInfo>>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = ResolverMap::new(&[cfg], &self.ksym_cache, &self.elf_cache)?;
        let mut syms_list = vec![];
        for name in names {
            let mut found = vec![];
            for (_, resolver) in &resolver_map.resolvers {
                if let Some(mut syms) = resolver.find_address(name, &ctx) {
                    for sym in &mut syms {
                        if ctx.offset_in_file {
                            if let Some(off) = resolver.addr_file_off(sym.address) {
                                sym.file_offset = off;
                            }
                        }
                        if ctx.obj_file_name {
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

    /// Find the addresses of a list of symbol names.
    ///
    /// Find the addresses of a list of symbol names from the sources
    /// of symbols and debug info described by `sym_srcs`.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `names` - A list of symbol names.
    pub fn find_addresses(
        &self,
        cfg: &SymbolSrcCfg,
        names: &[&str],
    ) -> Result<Vec<Vec<SymbolInfo>>> {
        self.find_addresses_opt(cfg, names, &[])
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
                    start_address: 0,
                    path: linfo.path,
                    line_no: linfo.line_no,
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
                        start_address: start,
                        path: linfo.path.clone(),
                        line_no: linfo.line_no,
                        column: linfo.column,
                    });
                } else {
                    let (sym, start) = sym;
                    results.push(SymbolizedResult {
                        symbol: String::from(sym),
                        start_address: start,
                        path: PathBuf::new(),
                        line_no: 0,
                        column: 0,
                    });
                }
            }
            results
        }
    }

    fn resolve_addr_in_binary(&self, addr: Addr, path: &Path) -> Result<Vec<SymbolizedResult>> {
        let backend = self.elf_cache.find(path)?;
        let resolver = ElfResolver::new(path, 0, backend)?;
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
        cfg: &cfg::Kernel,
    ) -> Result<Vec<Vec<SymbolizedResult>>> {
        let cfg::Kernel {
            kallsyms,
            kernel_image,
        } = cfg;

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
                let result = self.elf_cache.find(&image);
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
        let symbols = addrs
            .iter()
            .map(|addr| self.symbolize_with_resolver(*addr, &resolver))
            .collect();
        Ok(symbols)
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses according to the configuration
    /// provided via `cfg`.
    pub fn symbolize(
        &self,
        cfg: &SymbolSrcCfg,
        addrs: &[Addr],
    ) -> Result<Vec<Vec<SymbolizedResult>>> {
        if let SymbolSrcCfg::Process(cfg::Process { pid }) = cfg {
            return self.symbolize_user_addrs(addrs, *pid)
        }
        if let SymbolSrcCfg::Kernel(kernel) = cfg {
            return self.symbolize_kernel_addrs(addrs, kernel)
        }

        let resolver_map = ResolverMap::new(&[cfg], &self.ksym_cache, &self.elf_cache)?;

        let info = addrs
            .iter()
            .map(|addr| {
                let resolver = if let Some(resolver) = resolver_map.find_resolver(*addr) {
                    resolver
                } else {
                    return vec![]
                };

                self.symbolize_with_resolver(*addr, resolver)
            })
            .collect();

        Ok(info)
    }
}

// A library symbolizes addresses to symbols, filenames, and line numbers.
//
// BlazeSym is a library to symbolize addresses to get symbol names, file
// names of source files, and line numbers.  It can translate a stack
// trace to function names and their locations in the
// source code.
#![doc = include_str!("../README.md")]
#![allow(clippy::let_and_return, clippy::let_unit_value)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
#![cfg_attr(feature = "nightly", feature(test))]

#[cfg(feature = "nightly")]
extern crate test;

mod c_api;
mod dwarf;
mod elf;
mod gsym;
mod kernel;
mod ksym;
mod maps;
mod mmap;
mod resolver;
mod util;
// TODO: Remove `allow`.
#[allow(unused)]
mod zip;

use std::fmt::Debug;
use std::io::Error;
use std::io::Result;
use std::path::PathBuf;

use elf::ElfCache;
use ksym::KSymCache;
use resolver::ResolverMap;
use resolver::SymResolver;

pub use c_api::*;

pub type Addr = usize;


#[cfg(feature = "log")]
#[macro_use]
mod log {
    pub use log::debug;
    pub use log::error;
    pub use log::info;
    pub use log::trace;
    pub use log::warn;
}
#[cfg(not(feature = "log"))]
#[macro_use]
mod log {
    #[macro_export]
    macro_rules! debug {
        ($($args:tt)*) => {{
          if false {
            // Make sure to use `args` to prevent any warnings about
            // unused variables.
            let _args = format_args!($($args)*);
          }
        }};
    }
    pub use debug as error;
    pub use debug as info;
    pub use debug as trace;
    pub use debug as warn;
}


struct AddressLineInfo {
    pub path: String,
    pub line_no: usize,
    pub column: usize,
}

/// Types of symbols.
#[derive(Clone, Copy, Debug)]
pub enum SymbolType {
    Unknown,
    Function,
    Variable,
}

/// The context of an address finding request.
///
/// This type passes additional parameters to resolvers.
#[derive(Debug)]
pub(crate) struct FindAddrOpts {
    /// Return the offset of the symbol from the first byte of the
    /// object file if it is true. (False by default)
    offset_in_file: bool,
    /// Return the name of the object file if it is true. (False by default)
    obj_file_name: bool,
    /// Return the symbol(s) matching a given type. Unknown, by default,
    /// means all types.
    sym_type: SymbolType,
}

/// Information of a symbol.
#[derive(Debug)]
pub struct SymbolInfo {
    /// The name of the symbol; for example, a function name.
    pub name: String,
    /// Start address (the first byte) of the symbol
    pub address: Addr,
    /// The size of the symbol. The size of a function for example.
    pub size: usize,
    /// A function or a variable.
    pub sym_type: SymbolType,
    /// The offset in the object file.
    pub file_offset: u64,
    /// The file name of the shared object.
    pub obj_file_name: Option<PathBuf>,
}


pub mod cfg {
    use std::path::PathBuf;

    use super::Addr;
    use super::SymbolSrcCfg;


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


    /// This one will be expended into all ELF files in a process.
    ///
    /// With a `None` value, it would mean a process calling BlazeSym.
    #[derive(Clone, Debug)]
    pub struct Process {
        pub pid: Option<u32>,
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
    pub path: String,
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
        let ksym_cache = ksym::KSymCache::new();

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

        let ksym_cache = ksym::KSymCache::new();
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
        sym_srcs: &[SymbolSrcCfg],
        pattern: &str,
        features: &[FindAddrFeature],
    ) -> Option<Vec<SymbolInfo>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = match ResolverMap::new(sym_srcs, &self.ksym_cache, &self.elf_cache) {
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
    pub fn find_address_regex(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        pattern: &str,
    ) -> Option<Vec<SymbolInfo>> {
        self.find_address_regex_opt(sym_srcs, pattern, &[])
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
        sym_srcs: &[SymbolSrcCfg],
        names: &[&str],
        features: &[FindAddrFeature],
    ) -> Result<Vec<Vec<SymbolInfo>>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = ResolverMap::new(sym_srcs, &self.ksym_cache, &self.elf_cache)?;
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
        sym_srcs: &[SymbolSrcCfg],
        names: &[&str],
    ) -> Result<Vec<Vec<SymbolInfo>>> {
        self.find_addresses_opt(sym_srcs, names, &[])
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses with the information from the
    /// sources of symbols and debug info described by `sym_srcs`.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `addresses` - A list of addresses to symbolize.
    pub fn symbolize(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        addresses: &[Addr],
    ) -> Result<Vec<Vec<SymbolizedResult>>> {
        let resolver_map = ResolverMap::new(sym_srcs, &self.ksym_cache, &self.elf_cache)?;

        let info: Vec<Vec<SymbolizedResult>> = addresses
            .iter()
            .map(|addr| {
                let resolver = if let Some(resolver) = resolver_map.find_resolver(*addr) {
                    resolver
                } else {
                    return vec![]
                };

                let res_syms = resolver.find_symbols(*addr);
                let linfo = if self.line_number_info {
                    resolver.find_line_info(*addr)
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
                                path: "".to_string(),
                                line_no: 0,
                                column: 0,
                            });
                        }
                    }
                    results
                }
            })
            .collect();

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use test_log::test;


    #[test]
    fn load_symbolfilecfg_process() {
        // Check if SymbolSrcCfg::Process expands to ELFResolvers.
        let cfg = vec![SymbolSrcCfg::Process(cfg::Process { pid: None })];
        let line_number_info = true;
        let debug_info_symbols = false;
        let ksym_cache = ksym::KSymCache::new();
        let elf_cache = ElfCache::new(line_number_info, debug_info_symbols);
        let resolver_map = ResolverMap::new(&cfg, &ksym_cache, &elf_cache);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map
            .resolvers
            .iter()
            .map(|(_, resolver)| format!("{resolver:?}"))
            .collect();
        // ElfResolver for the binary itself.
        assert!(signatures.iter().any(|x| x.contains("/blazesym")));
        // ElfResolver for libc.
        assert!(signatures.iter().any(|x| x.contains("/libc")));
    }

    #[test]
    fn load_symbolfilecfg_processkernel() {
        let kallsyms = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("kallsyms");

        // Check if SymbolSrcCfg::Process & SymbolSrcCfg::Kernel expands to
        // ELFResolvers and a KernelResolver.
        let srcs = vec![
            SymbolSrcCfg::Process(cfg::Process { pid: None }),
            SymbolSrcCfg::Kernel(cfg::Kernel {
                kallsyms: Some(kallsyms),
                kernel_image: None,
            }),
        ];
        let line_number_info = true;
        let debug_info_symbols = false;
        let ksym_cache = ksym::KSymCache::new();
        let elf_cache = ElfCache::new(line_number_info, debug_info_symbols);
        let resolver_map = ResolverMap::new(&srcs, &ksym_cache, &elf_cache).unwrap();

        let signatures: Vec<_> = resolver_map
            .resolvers
            .iter()
            .map(|(_, resolver)| format!("{resolver:?}"))
            .collect();
        // ElfResolver for the binary itself.
        assert!(signatures.iter().any(|x| x.contains("/blazesym")));
        // ElfResolver for libc.
        assert!(signatures.iter().any(|x| x.contains("/libc")));
        assert!(signatures.iter().any(|x| x.contains("KernelResolver")));
    }
}

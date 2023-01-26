// A library symbolizes addresses to symbols, filenames, and line numbers.
//
// BlazeSym is a library to symbolize addresses to get symbol names, file
// names of source files, and line numbers.  It can translate a stack
// trace to function names and their locations in the
// source code.
#![doc = include_str!("../README.md")]
#![allow(dead_code, clippy::let_and_return)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(feature = "nightly", feature(test))]

#[cfg(feature = "nightly")]
extern crate test;

use std::ffi::CStr;
use std::ffi::OsStr;
use std::io::{Error, ErrorKind};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::u64;

use std::ptr;

use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::os::raw::c_char;
use std::rc::Rc;

use nix::sys::stat::stat;
use nix::sys::utsname;

#[doc(hidden)]
mod dwarf;
mod elf;
mod elf_cache;
mod gsym;
mod ksym;
mod tools;

use elf_cache::{ElfBackend, ElfCache};
use gsym::GsymResolver;
use ksym::{KSymCache, KSymResolver};

struct CacheHolder {
    ksym: KSymCache,
    elf: ElfCache,
}

struct CacheHolderOpts {
    line_number_info: bool,
    debug_info_symbols: bool,
}

impl CacheHolder {
    fn new(opts: CacheHolderOpts) -> CacheHolder {
        CacheHolder {
            ksym: ksym::KSymCache::new(),
            elf: elf_cache::ElfCache::new(opts.line_number_info, opts.debug_info_symbols),
        }
    }

    fn get_ksym_cache(&self) -> &KSymCache {
        &self.ksym
    }

    fn get_elf_cache(&self) -> &ElfCache {
        &self.elf
    }
}

#[doc(hidden)]
pub trait StackFrame {
    fn get_ip(&self) -> u64;
    fn get_frame_pointer(&self) -> u64;
}

#[doc(hidden)]
pub trait StackSession {
    fn next_frame(&mut self) -> Option<&dyn StackFrame>;
    fn prev_frame(&mut self) -> Option<&dyn StackFrame>;
    fn go_top(&mut self);
}

struct AddressLineInfo {
    pub path: String,
    pub line_no: usize,
    pub column: usize,
}

/// Types of symbols..
#[derive(Clone, Copy)]
pub enum SymbolType {
    Unknown,
    Function,
    Variable,
}

/// The context of an address finding request.
///
/// This type passes additional parameters to resolvers.
#[doc(hidden)]
pub struct FindAddrOpts {
    /// Return the offset of the symbol from the first byte of the
    /// object file if it is true. (False by default)
    offset_in_file: bool,
    /// Return the name of the object file if it is true. (False by default)
    obj_file_name: bool,
    /// Return the symbol(s) matching a given type. Unknown, by default, mean all types.
    sym_type: SymbolType,
}

/// Information of a symbol.
pub struct SymbolInfo {
    /// The name of the symbol; for example, a function name.
    pub name: String,
    /// Start address (the first byte) of the symbol
    pub address: u64,
    /// The size of the symbol. The size of a function for example.
    pub size: u64,
    /// A function or a variable.
    pub sym_type: SymbolType,
    /// The offset in the object file.
    pub file_offset: u64,
    /// The file name of the shared object.
    pub obj_file_name: Option<PathBuf>,
}

impl Default for SymbolInfo {
    fn default() -> Self {
        SymbolInfo {
            name: "".to_string(),
            address: 0,
            size: 0,
            sym_type: SymbolType::Unknown,
            file_offset: 0,
            obj_file_name: None,
        }
    }
}

/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e., a symbol file.
trait SymResolver {
    /// Return the range that this resolver serve in an address space.
    fn get_address_range(&self) -> (u64, u64);
    /// Find the names and the start addresses of a symbol found for
    /// the given address.
    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)>;
    /// Find the address and size of a symbol name.
    fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the addresses and sizes of the symbols matching a given pattern.
    fn find_address_regex(&self, pattern: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo>;
    /// Translate an address (virtual) in a process to the file offset
    /// in the object file.
    fn addr_file_off(&self, addr: u64) -> Option<u64>;
    /// Get the file name of the shared object.
    fn get_obj_file_name(&self) -> &Path;

    fn repr(&self) -> String;
}

#[doc(hidden)]
pub const REG_RAX: usize = 0;
#[doc(hidden)]
pub const REG_RBX: usize = 1;
#[doc(hidden)]
pub const REG_RCX: usize = 2;
#[doc(hidden)]
pub const REG_RDX: usize = 3;
#[doc(hidden)]
pub const REG_RSI: usize = 4;
#[doc(hidden)]
pub const REG_RDI: usize = 5;
#[doc(hidden)]
pub const REG_RSP: usize = 6;
#[doc(hidden)]
pub const REG_RBP: usize = 7;
#[doc(hidden)]
pub const REG_R8: usize = 8;
#[doc(hidden)]
pub const REG_R9: usize = 9;
#[doc(hidden)]
pub const REG_R10: usize = 10;
#[doc(hidden)]
pub const REG_R11: usize = 11;
#[doc(hidden)]
pub const REG_R12: usize = 12;
#[doc(hidden)]
pub const REG_R13: usize = 13;
#[doc(hidden)]
pub const REG_R14: usize = 14;
#[doc(hidden)]
pub const REG_R15: usize = 15;
#[doc(hidden)]
pub const REG_RIP: usize = 16;

struct X86_64StackFrame {
    rip: u64,
    rbp: u64,
}

impl StackFrame for X86_64StackFrame {
    fn get_ip(&self) -> u64 {
        self.rip
    }
    fn get_frame_pointer(&self) -> u64 {
        self.rbp
    }
}

/// Do stacking unwind for x86_64
///
/// Parse a block of memory that is a copy of stack of thread to get frames.
///
#[doc(hidden)]
pub struct X86_64StackSession {
    frames: Vec<X86_64StackFrame>,
    stack: Vec<u8>,
    stack_base: u64, // The base address of the stack
    registers: [u64; 17],
    current_rbp: u64,
    current_rip: u64,
    current_frame_idx: usize,
}

impl X86_64StackSession {
    fn _get_rbp_rel(&self) -> usize {
        (self.current_rbp - self.stack_base) as usize
    }

    fn _mark_at_bottom(&mut self) {
        self.current_rbp = 0;
    }

    fn _is_at_bottom(&self) -> bool {
        self.current_rbp == 0
    }

    fn _get_u64(&self, off: usize) -> u64 {
        let stack = &self.stack;
        (stack[off] as u64)
            | ((stack[off + 1] as u64) << 8)
            | ((stack[off + 2] as u64) << 16)
            | ((stack[off + 3] as u64) << 24)
            | ((stack[off + 4] as u64) << 32)
            | ((stack[off + 5] as u64) << 40)
            | ((stack[off + 6] as u64) << 48)
            | ((stack[off + 7] as u64) << 56)
    }

    pub fn new(stack: Vec<u8>, stack_base: u64, registers: [u64; 17]) -> X86_64StackSession {
        X86_64StackSession {
            frames: Vec::new(),
            stack,
            stack_base,
            registers,
            current_rbp: registers[REG_RBP],
            current_rip: registers[REG_RIP],
            current_frame_idx: 0,
        }
    }
}

impl StackSession for X86_64StackSession {
    fn next_frame(&mut self) -> Option<&dyn StackFrame> {
        if self._is_at_bottom() {
            return None;
        }

        if self.frames.len() > self.current_frame_idx {
            let frame = &self.frames[self.current_frame_idx];
            self.current_frame_idx += 1;
            return Some(frame);
        }

        let frame = X86_64StackFrame {
            rip: self.current_rip,
            rbp: self.current_rbp,
        };
        self.frames.push(frame);

        if self._get_rbp_rel() <= (self.stack.len() - 16) {
            let new_rbp = self._get_u64(self._get_rbp_rel());
            let new_rip = self._get_u64(self._get_rbp_rel() + 8);
            self.current_rbp = new_rbp;
            self.current_rip = new_rip;
        } else {
            self._mark_at_bottom();
        }

        self.current_frame_idx += 1;
        Some(self.frames.last().unwrap() as &dyn StackFrame)
    }

    fn prev_frame(&mut self) -> Option<&dyn StackFrame> {
        if self.current_frame_idx == 0 {
            return None;
        }

        self.current_frame_idx -= 1;
        Some(&self.frames[self.current_frame_idx] as &dyn StackFrame)
    }

    fn go_top(&mut self) {
        self.current_rip = self.registers[REG_RIP];
        self.current_rbp = self.registers[REG_RBP];
        self.current_frame_idx = 0;
    }
}

/// Create a KSymResolver
///
/// # Safety
///
/// This function is supposed to be used by C code.  The pointer
/// returned should be free with `sym_resolver_free()`.
///
#[no_mangle]
#[doc(hidden)]
pub unsafe extern "C" fn sym_resolver_create() -> *mut KSymResolver {
    let mut resolver = Box::new(KSymResolver::new());
    if resolver.load().is_err() {
        ptr::null_mut()
    } else {
        Box::leak(resolver)
    }
}

/// The symbol resolver for a single ELF file.
///
/// An ELF file may be loaded into an address space with a relocation.
/// The callers should provide the path of an ELF file and where it's
/// executable segment(s) is loaded.
///
/// For some ELF files, they are located at a specific address
/// determined during compile-time.  For these cases, just pass `0` as
/// it's loaded address.
struct ElfResolver {
    backend: ElfBackend,
    loaded_address: u64,
    loaded_to_virt: u64,
    foff_to_virt: u64,
    size: u64,
    file_name: PathBuf,
}

impl ElfResolver {
    fn new(
        file_name: &Path,
        loaded_address: u64,
        cache_holder: &CacheHolder,
    ) -> Result<ElfResolver, Error> {
        let backend = cache_holder.get_elf_cache().find(file_name)?;
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
        if e_type == elf::ET_DYN || e_type == elf::ET_EXEC {
            for phdr in phdrs {
                if phdr.p_type != elf::PT_LOAD {
                    continue;
                }
                if (phdr.p_flags & elf::PF_X) != elf::PF_X {
                    continue;
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
            return Err(Error::new(ErrorKind::InvalidData, "unknown e_type"));
        }

        let loaded_address = if e_type == elf::ET_EXEC {
            low_addr
        } else {
            loaded_address
        };
        let loaded_to_virt = low_addr;
        let foff_to_virt = low_addr - low_off;
        let size = max_addr - low_addr;

        Ok(ElfResolver {
            backend,
            loaded_address,
            loaded_to_virt,
            foff_to_virt,
            size,
            file_name: file_name.to_path_buf(),
        })
    }

    fn get_parser(&self) -> Option<&elf::Elf64Parser> {
        match &self.backend {
            ElfBackend::Dwarf(dwarf) => Some(dwarf.get_parser()),
            ElfBackend::Elf(parser) => Some(parser),
        }
    }
}

impl SymResolver for ElfResolver {
    fn get_address_range(&self) -> (u64, u64) {
        (self.loaded_address, self.loaded_address + self.size)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
        let off = addr - self.loaded_address + self.loaded_to_virt;
        let parser = if let Some(parser) = self.get_parser() {
            parser
        } else {
            return vec![];
        };

        match parser.find_symbol(off, elf::STT_FUNC) {
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
            return None;
        }
        let mut syms = syms.unwrap();
        for sym in &mut syms {
            sym.address = sym.address - self.loaded_to_virt + self.loaded_address;
        }
        Some(syms)
    }

    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
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

    fn addr_file_off(&self, addr: u64) -> Option<u64> {
        Some(addr - self.loaded_address + self.loaded_to_virt - self.foff_to_virt)
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }

    fn repr(&self) -> String {
        match self.backend {
            ElfBackend::Dwarf(_) => format!("DWARF {}", self.file_name.display()),
            ElfBackend::Elf(_) => format!("ELF {}", self.file_name.display()),
        }
    }
}

struct KernelResolver {
    ksymresolver: Option<Rc<KSymResolver>>,
    kernelresolver: Option<ElfResolver>,
    kallsyms: PathBuf,
    kernel_image: PathBuf,
}

impl KernelResolver {
    fn new(
        kallsyms: &Path,
        kernel_image: &Path,
        cache_holder: &CacheHolder,
    ) -> Result<KernelResolver, Error> {
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
            ));
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
    fn get_address_range(&self) -> (u64, u64) {
        (0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
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
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
        self.kernelresolver.as_ref()?;
        self.kernelresolver.as_ref().unwrap().find_line_info(addr)
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.kernel_image
    }

    fn repr(&self) -> String {
        format!(
            "KernelResolver {} {}",
            self.kallsyms.display(),
            self.kernel_image.display()
        )
    }
}

/// The description of a source of symbols and debug information.
///
/// The source of symbols and debug information can be an ELF file, kernel
/// image, or process.
#[derive(Clone)]
pub enum SymbolSrcCfg {
    /// A single ELF file
    ///
    /// You should provide the name of an ELF file and its base address.
    ///
    Elf {
        /// The name of ELF files.
        ///
        /// It can be an executable or shared object.
        /// For example, passing `"/bin/sh"` will load symbols and debug information from `sh`.
        /// Whereas passing `"/lib/libc.so.xxx"` will load symbols and debug information from the libc.
        file_name: PathBuf,
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
        base_address: u64,
    },
    /// Linux Kernel's binary image and a copy of /proc/kallsyms
    Kernel {
        /// The path of a kallsyms copy.
        ///
        /// For the running kernel on the device, it can be
        /// "/proc/kallsyms".  However, you can make a copy for later.
        /// In that situation, you should give the path of the
        /// copy.  Passing `None`, by default, will be
        /// `"/proc/kallsyms"`.
        kallsyms: Option<PathBuf>,
        /// The path of a kernel image.
        ///
        /// This should be the path of a kernel image.  For example,
        /// `"/boot/vmlinux-xxxx"`.  A `None` value will find the
        /// kernel image of the running kernel in `"/boot/"` or
        /// `"/usr/lib/debug/boot/"`.
        kernel_image: Option<PathBuf>,
    },
    /// This one will be expended into all ELF files in a process.
    ///
    /// With a `None` value, it would means a process calling BlazeSym.
    Process { pid: Option<u32> },
    Gsym {
        file_name: PathBuf,
        base_address: u64,
    },
}

/// The result of symbolization by BlazeSymbolizer.
///
/// [`BlazeSymbolizer::symbolize()`] returns a list of lists of
/// `SymbolizedResult`.  It appears as `[[SymbolizedResult {...},
/// SymbolizedResult {...}, ...], [SymbolizedResult {...}, ...],
/// ...]`.  At the first level, each entry is a list of
/// `SymbolizedResult`.  [`BlazeSymbolizer::symbolize()`] can return
/// multiple results of an address due to compiler optimizations.
#[derive(Clone)]
pub struct SymbolizedResult {
    /// The symbol name that an address may belong to.
    pub symbol: String,
    /// The address where the symbol is located within the process.
    ///
    /// The address is in the target process, not the offset from the
    /// shared object file.
    pub start_address: u64,
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

type ResolverList = Vec<((u64, u64), Box<dyn SymResolver>)>;

struct ResolverMap {
    resolvers: ResolverList,
}

impl ResolverMap {
    fn build_resolvers_proc_maps(
        pid: u32,
        resolvers: &mut ResolverList,
        cache_holder: &CacheHolder,
    ) -> Result<(), Error> {
        let entries = tools::parse_maps(pid)?;

        for entry in entries.iter() {
            if entry.path.as_path().components().next() != Some(Component::RootDir) {
                continue;
            }
            if (entry.mode & 0xa) != 0xa {
                // r-x-
                continue;
            }

            if let Ok(filestat) = stat(&entry.path) {
                if (filestat.st_mode & 0o170000) != 0o100000 {
                    // Not a regular file
                    continue;
                }
            } else {
                continue;
            }
            if let Ok(resolver) = ElfResolver::new(&entry.path, entry.loaded_address, cache_holder)
            {
                resolvers.push((resolver.get_address_range(), Box::new(resolver)));
            } else {
                #[cfg(debug_assertions)]
                eprintln!("Fail to create ElfResolver for {}", entry.path.display());
            }
        }

        Ok(())
    }

    pub fn new(
        sym_srcs: &[SymbolSrcCfg],
        cache_holder: &CacheHolder,
    ) -> Result<ResolverMap, Error> {
        let mut resolvers = ResolverList::new();
        for cfg in sym_srcs {
            match cfg {
                SymbolSrcCfg::Elf {
                    file_name,
                    base_address,
                } => {
                    let resolver = ElfResolver::new(file_name, *base_address, cache_holder)?;
                    resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Kernel {
                    kallsyms,
                    kernel_image,
                } => {
                    let kallsyms = kallsyms
                        .as_deref()
                        .unwrap_or_else(|| Path::new("/proc/kallsyms"));
                    let kernel_image = if let Some(img) = kernel_image {
                        img.clone()
                    } else {
                        let release = utsname::uname()?.release().to_str().unwrap().to_string();
                        let basename = "vmlinux-";
                        let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
                        let mut i = 0;
                        let kernel_image = loop {
                            let path = dirs[i].join(format!("{basename}{release}"));
                            if stat(&path).is_ok() {
                                break path;
                            }
                            i += 1;
                            if i >= dirs.len() {
                                break path;
                            }
                        };
                        kernel_image
                    };
                    if let Ok(resolver) = KernelResolver::new(kallsyms, &kernel_image, cache_holder)
                    {
                        resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                    } else {
                        #[cfg(debug_assertions)]
                        eprintln!("fail to load the kernel image {}", kernel_image.display());
                    }
                }
                SymbolSrcCfg::Process { pid } => {
                    let pid = if let Some(p) = pid { *p } else { 0 };

                    if let Err(_e) =
                        Self::build_resolvers_proc_maps(pid, &mut resolvers, cache_holder)
                    {
                        #[cfg(debug_assertions)]
                        eprintln!("Fail to load symbols for the process {pid}: {_e:?}");
                    }
                }
                SymbolSrcCfg::Gsym {
                    file_name,
                    base_address,
                } => {
                    let resolver = GsymResolver::new(file_name.clone(), *base_address)?;
                    resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
            };
        }
        resolvers.sort_by_key(|x| x.0 .0); // sorted by the loaded addresses

        Ok(ResolverMap { resolvers })
    }

    pub fn find_resolver(&self, address: u64) -> Option<&dyn SymResolver> {
        let idx =
            tools::search_address_key(&self.resolvers, address, &|map: &(
                (u64, u64),
                Box<dyn SymResolver>,
            )|
             -> u64 { map.0 .0 })?;
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

/// Switches in the features of BlazeSymbolizer.
///
/// Passing variants of this `enum` to [`BlazeSymbolizer::new_opt()`]
/// will enable (true) or disable (false) respective features
/// of a symbolizer.
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
pub enum FindAddrFeature {
    /// Return the offset in the file.
    ///
    /// The offset will be returned as the value of `SymbolInfo::file_offset`.
    /// (Off by default)
    OffsetInFile(bool),
    /// Return the file name of the shared object.
    ///
    /// The name of the executiable or object file will be returned as
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
pub struct BlazeSymbolizer {
    cache_holder: CacheHolder,

    line_number_info: bool,
}

impl BlazeSymbolizer {
    /// Create and return an instance of BlazeSymbolizer.
    pub fn new() -> Result<BlazeSymbolizer, Error> {
        let opts = CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        };
        let cache_holder = CacheHolder::new(opts);

        Ok(BlazeSymbolizer {
            cache_holder,
            line_number_info: true,
        })
    }

    /// Create and return an instance of BlazeSymbolizer.
    ///
    /// `new_opt()` works like [`BlazeSymbolizer::new()`] except it receives a list of
    /// [`SymbolizerFeature`] to turn on or off some features.
    pub fn new_opt(features: &[SymbolizerFeature]) -> Result<BlazeSymbolizer, Error> {
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

        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info,
            debug_info_symbols,
        });

        Ok(BlazeSymbolizer {
            cache_holder,
            line_number_info,
        })
    }

    fn find_addr_features_context(features: Vec<FindAddrFeature>) -> FindAddrOpts {
        let mut opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        for f in features {
            match f {
                FindAddrFeature::OffsetInFile(enable) => {
                    opts.offset_in_file = enable;
                }
                FindAddrFeature::ObjFileName(enable) => {
                    opts.obj_file_name = enable;
                }
                FindAddrFeature::SymbolType(sym_type) => {
                    opts.sym_type = sym_type;
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
        features: Vec<FindAddrFeature>,
    ) -> Option<Vec<SymbolInfo>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = match ResolverMap::new(sym_srcs, &self.cache_holder) {
            Ok(map) => map,
            _ => {
                return None;
            }
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
        self.find_address_regex_opt(sym_srcs, pattern, vec![])
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
        features: Vec<FindAddrFeature>,
    ) -> Vec<Vec<SymbolInfo>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = match ResolverMap::new(sym_srcs, &self.cache_holder) {
            Ok(map) => map,
            _ => {
                return vec![];
            }
        };
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
        syms_list
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
    ) -> Vec<Vec<SymbolInfo>> {
        self.find_addresses_opt(sym_srcs, names, vec![])
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
        addresses: &[u64],
    ) -> Vec<Vec<SymbolizedResult>> {
        let resolver_map = if let Ok(map) = ResolverMap::new(sym_srcs, &self.cache_holder) {
            map
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to build ResolverMap");
            return vec![];
        };

        let info: Vec<Vec<SymbolizedResult>> = addresses
            .iter()
            .map(|addr| {
                let resolver = if let Some(resolver) = resolver_map.find_resolver(*addr) {
                    resolver
                } else {
                    return vec![];
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
        info
    }
}

/// Types of symbol sources and debug information for C API.
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum blazesym_src_type {
    /// Symbols and debug information from an ELF file.
    SRC_T_ELF,
    /// Symbols and debug information from a kernel image and its kallsyms.
    SRC_T_KERNEL,
    /// Symbols and debug information from a process, including loaded object files.
    SRC_T_PROCESS,
}

/// The parameters to load symbols and debug information from an ELF.
///
/// Describes the path and address of an ELF file loaded in a
/// process.
#[repr(C)]
pub struct ssc_elf {
    /// The file name of an ELF file.
    ///
    /// It can be an executable or shared object.
    /// For example, passing "/bin/sh" will load symbols and debug information from `sh`.
    /// Whereas passing "/lib/libc.so.xxx" will load symbols and debug information from the libc.
    pub file_name: *const c_char,
    /// The base address is where the file's executable segment(s) is loaded.
    ///
    /// It should be the address
    /// in the process mapping to the executable segment's first byte.
    /// For example, in /proc/&lt;pid&gt;/maps
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
    /// A loader would load an executable segment with the permission of `x`
    /// (executable).  For example, the first block is with the
    /// permission of `r-xp`.
    pub base_address: u64,
}

/// The parameters to load symbols and debug information from a kernel.
///
/// Use a kernel image and a snapshot of its kallsyms as a source of symbols and
/// debug information.
#[repr(C)]
pub struct ssc_kernel {
    /// The path of a copy of kallsyms.
    ///
    /// It can be `"/proc/kallsyms"` for the running kernel on the
    /// device.  However, you can make copies for later.  In that situation,
    /// you should give the path of a copy.
    /// Passing a `NULL`, by default, will result in `"/proc/kallsyms"`.
    pub kallsyms: *const c_char,
    /// The path of a kernel image.
    ///
    /// The path of a kernel image should be, for instance,
    /// `"/boot/vmlinux-xxxx"`.  For a `NULL` value, it will locate the
    /// kernel image of the running kernel in `"/boot/"` or
    /// `"/usr/lib/debug/boot/"`.
    pub kernel_image: *const c_char,
}

/// The parameters to load symbols and debug information from a process.
///
/// Load all ELF files in a process as the sources of symbols and debug
/// information.
#[repr(C)]
pub struct ssc_process {
    /// It is the PID of a process to symbolize.
    ///
    /// BlazeSym will parse `/proc/<pid>/maps` and load all the object
    /// files.
    pub pid: u32,
}

/// Parameters of a symbol source.
#[repr(C)]
pub union ssc_params {
    /// The variant for SRC_T_ELF
    pub elf: mem::ManuallyDrop<ssc_elf>,
    /// The variant for SRC_T_KERNEL
    pub kernel: mem::ManuallyDrop<ssc_kernel>,
    /// The variant for SRC_T_PROCESS
    pub process: mem::ManuallyDrop<ssc_process>,
}

/// Description of a source of symbols and debug information for C API.
#[repr(C)]
pub struct sym_src_cfg {
    /// A type of symbol source.
    pub src_type: blazesym_src_type,
    pub params: ssc_params,
}

/// Names of the BlazeSym features.
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum blazesym_feature_name {
    /// Enable or disable returning line numbers of addresses.
    ///
    /// Users should set `blazesym_feature.params.enable` to enabe or
    /// disable the feature,
    LINE_NUMBER_INFO,
    /// Enable or disable loading symbols from DWARF.
    ///
    /// Users should `blazesym_feature.params.enable` to enable or
    /// disable the feature.  This feature is disabled by default.
    DEBUG_INFO_SYMBOLS,
}

#[repr(C)]
pub union blazesym_feature_params {
    enable: bool,
}

/// Setting of the blazesym features.
///
/// Contain parameters to enable, disable, or customize a feature.
#[repr(C)]
pub struct blazesym_feature {
    pub feature: blazesym_feature_name,
    pub params: blazesym_feature_params,
}

/// A placeholder symbolizer for C API.
///
/// It is returned by [`blazesym_new()`] and should be free by
/// [`blazesym_free()`].
#[repr(C)]
pub struct blazesym {
    symbolizer: *mut BlazeSymbolizer,
}

/// The result of symbolization of an address for C API.
///
/// A `blazesym_csym` is the information of a symbol found for an
/// address.  One address may result in several symbols.
#[repr(C)]
pub struct blazesym_csym {
    /// The symbol name is where the given address should belong to.
    pub symbol: *const c_char,
    /// The address (i.e.,the first byte) is where the symbol is located.
    ///
    /// The address is already relocated to the address space of
    /// the process.
    pub start_address: u64,
    /// The path of the source code defines the symbol.
    pub path: *const c_char,
    /// The instruction of the address is in the line number of the source code.
    pub line_no: usize,
    pub column: usize,
}

/// `blazesym_entry` is the output of symbolization for an address for C API.
///
/// Every address has an `blazesym_entry` in
/// [`blazesym_result::entries`] to collect symbols found by BlazeSym.
#[repr(C)]
pub struct blazesym_entry {
    /// The number of symbols found for an address.
    pub size: usize,
    /// All symbols found.
    ///
    /// `syms` is an array of blazesym_csym in the size `size`.
    pub syms: *const blazesym_csym,
}

/// `blazesym_result` is the result of symbolization for C API.
///
/// The instances of blazesym_result are returned from
/// [`blazesym_symbolize()`].  They should be free by calling
/// [`blazesym_result_free()`].
#[repr(C)]
pub struct blazesym_result {
    /// The number of addresses being symbolized.
    pub size: usize,
    /// The entries for addresses.
    ///
    /// Symbolization occurs based on the order of addresses.
    /// Therefore, every address must have an entry here on the same
    /// order.
    pub entries: [blazesym_entry; 0],
}

/// Create a `PathBuf` from a pointer of C string
///
/// # Safety
///
/// C string should be terminated with a null byte.
///
unsafe fn from_cstr(cstr: *const c_char) -> PathBuf {
    PathBuf::from(unsafe { CStr::from_ptr(cstr) }.to_str().unwrap())
}

unsafe fn symbolsrccfg_to_rust(cfg: *const sym_src_cfg, cfg_len: u32) -> Option<Vec<SymbolSrcCfg>> {
    let mut cfg_rs = Vec::<SymbolSrcCfg>::with_capacity(cfg_len as usize);

    for i in 0..cfg_len {
        let c = unsafe { cfg.offset(i as isize) };
        match unsafe { &(*c).src_type } {
            blazesym_src_type::SRC_T_ELF => {
                cfg_rs.push(SymbolSrcCfg::Elf {
                    file_name: unsafe { from_cstr((*c).params.elf.file_name) },
                    base_address: unsafe { (*c).params.elf.base_address },
                });
            }
            blazesym_src_type::SRC_T_KERNEL => {
                let kallsyms = unsafe { (*c).params.kernel.kallsyms };
                let kernel_image = unsafe { (*c).params.kernel.kernel_image };
                cfg_rs.push(SymbolSrcCfg::Kernel {
                    kallsyms: if !kallsyms.is_null() {
                        Some(unsafe { from_cstr(kallsyms) })
                    } else {
                        None
                    },
                    kernel_image: if !kernel_image.is_null() {
                        Some(unsafe { from_cstr(kernel_image) })
                    } else {
                        None
                    },
                });
            }
            blazesym_src_type::SRC_T_PROCESS => {
                let pid = unsafe { (*c).params.process.pid };
                cfg_rs.push(SymbolSrcCfg::Process {
                    pid: if pid > 0 { Some(pid) } else { None },
                });
            }
        }
    }

    Some(cfg_rs)
}

/// Create an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// Free the pointer with [`blazesym_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_new() -> *mut blazesym {
    let symbolizer = match BlazeSymbolizer::new() {
        Ok(s) => s,
        Err(_) => {
            return ptr::null_mut();
        }
    };
    let symbolizer_box = Box::new(symbolizer);
    let c_box = Box::new(blazesym {
        symbolizer: Box::into_raw(symbolizer_box),
    });
    Box::into_raw(c_box)
}

/// Create an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// Free the pointer with [`blazesym_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_new_opts(
    features: *const blazesym_feature,
    nfeatures: usize,
) -> *mut blazesym {
    let features_v = unsafe {
        Vec::<blazesym_feature>::from_raw_parts(
            features as *mut blazesym_feature,
            nfeatures,
            nfeatures,
        )
    };
    let features_v = mem::ManuallyDrop::new(features_v);
    let features_r: Vec<_> = features_v
        .iter()
        .map(|x| -> SymbolizerFeature {
            match x.feature {
                blazesym_feature_name::LINE_NUMBER_INFO => {
                    SymbolizerFeature::LineNumberInfo(unsafe { x.params.enable })
                }
                blazesym_feature_name::DEBUG_INFO_SYMBOLS => {
                    SymbolizerFeature::DebugInfoSymbols(unsafe { x.params.enable })
                }
            }
        })
        .collect();

    let symbolizer = match BlazeSymbolizer::new_opt(&features_r) {
        Ok(s) => s,
        Err(_) => {
            return ptr::null_mut();
        }
    };
    let symbolizer_box = Box::new(symbolizer);
    let c_box = Box::new(blazesym {
        symbolizer: Box::into_raw(symbolizer_box),
    });
    Box::into_raw(c_box)
}

/// Free an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_new()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_free(symbolizer: *mut blazesym) {
    if !symbolizer.is_null() {
        drop(unsafe { Box::from_raw((*symbolizer).symbolizer) });
        drop(unsafe { Box::from_raw(symbolizer) });
    }
}

/// Convert SymbolizedResults to blazesym_results.
///
/// # Safety
///
/// The returned pointer should be freed by [`blazesym_result_free()`].
///
unsafe fn convert_symbolizedresults_to_c(
    results: Vec<Vec<SymbolizedResult>>,
) -> *const blazesym_result {
    // Allocate a buffer to contain a blazesym_result, all
    // blazesym_csym, and C strings of symbol and path.
    let strtab_size = results.iter().flatten().fold(0, |acc, result| {
        acc + result.symbol.len() + result.path.len() + 2
    });
    let all_csym_size = results.iter().flatten().count();
    let buf_size = strtab_size
        + mem::size_of::<blazesym_result>()
        + mem::size_of::<blazesym_entry>() * results.len()
        + mem::size_of::<blazesym_csym>() * all_csym_size;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };
    if raw_buf_with_sz.is_null() {
        return ptr::null();
    }

    // prepend an u64 to keep the size of the buffer.
    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };

    let result_ptr = raw_buf as *mut blazesym_result;
    let mut entry_last = unsafe { &mut (*result_ptr).entries as *mut blazesym_entry };
    let mut csym_last = unsafe {
        raw_buf.add(
            mem::size_of::<blazesym_result>() + mem::size_of::<blazesym_entry>() * results.len(),
        )
    } as *mut blazesym_csym;
    let mut cstr_last = unsafe {
        raw_buf.add(
            mem::size_of::<blazesym_result>()
                + mem::size_of::<blazesym_entry>() * results.len()
                + mem::size_of::<blazesym_csym>() * all_csym_size,
        )
    } as *mut c_char;

    let mut make_cstr = |src: &str| {
        let cstr = cstr_last;
        unsafe { ptr::copy(src.as_ptr(), cstr as *mut u8, src.len()) };
        unsafe { *cstr.add(src.len()) = 0 };
        cstr_last = unsafe { cstr_last.add(src.len() + 1) };

        cstr
    };

    unsafe { (*result_ptr).size = results.len() };

    // Convert all SymbolizedResults to blazesym_entrys and blazesym_csyms
    for entry in results {
        unsafe { (*entry_last).size = entry.len() };
        unsafe { (*entry_last).syms = csym_last };
        entry_last = unsafe { entry_last.add(1) };

        for r in entry {
            let symbol_ptr = make_cstr(&r.symbol);

            let path_ptr = make_cstr(&r.path);

            let csym_ref = unsafe { &mut *csym_last };
            csym_ref.symbol = symbol_ptr;
            csym_ref.start_address = r.start_address;
            csym_ref.path = path_ptr;
            csym_ref.line_no = r.line_no;
            csym_ref.column = r.column;

            csym_last = unsafe { csym_last.add(1) };
        }
    }

    result_ptr
}

/// Symbolize addresses with the sources of symbols and debug info.
///
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses.  The caller should free the returned
/// array by calling [`blazesym_result_free()`].
///
/// # Safety
///
/// The returned pointer should be freed by [`blazesym_result_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_symbolize(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    addrs: *const u64,
    addr_cnt: usize,
) -> *const blazesym_result {
    let sym_srcs_rs =
        if let Some(sym_srcs_rs) = unsafe { symbolsrccfg_to_rust(sym_srcs, sym_srcs_len) } {
            sym_srcs_rs
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to transform configurations of symbolizer from C to Rust");
            return ptr::null_mut();
        };

    let symbolizer = unsafe { &*(*symbolizer).symbolizer };
    let addresses = unsafe { Vec::from_raw_parts(addrs as *mut u64, addr_cnt, addr_cnt) };

    let results = symbolizer.symbolize(&sym_srcs_rs, &addresses);

    addresses.leak();

    if results.is_empty() {
        #[cfg(debug_assertions)]
        eprintln!("Empty result while request for {addr_cnt}");
        return ptr::null();
    }

    unsafe { convert_symbolizedresults_to_c(results) }
}

/// Free an array returned by blazesym_symbolize.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_symbolize()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_result_free(results: *const blazesym_result) {
    if results.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("blazesym_result_free(null)");
        return;
    }

    let raw_buf_with_sz = unsafe { (results as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

#[repr(C)]
pub struct blazesym_sym_info {
    name: *const u8,
    address: u64,
    size: u64,
    sym_type: blazesym_sym_type,
    file_offset: u64,
    obj_file_name: *const u8,
}

/// Convert SymbolInfos returned by BlazeSymbolizer::find_addresses() to a C array.
unsafe fn convert_syms_list_to_c(
    syms_list: Vec<Vec<SymbolInfo>>,
) -> *const *const blazesym_sym_info {
    let mut sym_cnt = 0;
    let mut str_buf_sz = 0;

    for syms in &syms_list {
        sym_cnt += syms.len() + 1;
        for sym in syms {
            str_buf_sz += sym.name.len() + 1;
            if let Some(fname) = sym.obj_file_name.as_ref() {
                str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
            }
        }
    }

    let array_sz = ((mem::size_of::<*const u64>() * syms_list.len() + mem::size_of::<u64>() - 1)
        % mem::size_of::<u64>())
        * mem::size_of::<u64>();
    let sym_buf_sz = mem::size_of::<blazesym_sym_info>() * sym_cnt;
    let buf_size = array_sz + sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut syms_ptr = raw_buf as *mut *mut blazesym_sym_info;
    let mut sym_ptr = unsafe { raw_buf.add(array_sz) } as *mut blazesym_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(array_sz + sym_buf_sz) } as *mut u8;

    for syms in syms_list {
        unsafe { *syms_ptr = sym_ptr };
        for SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } in syms
        {
            let name_ptr = str_ptr as *const u8;
            unsafe { ptr::copy_nonoverlapping(name.as_ptr(), str_ptr, name.len()) };
            str_ptr = unsafe { str_ptr.add(name.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
                let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
                let obj_fname_ptr = str_ptr;
                unsafe { ptr::copy_nonoverlapping(fname.as_ptr(), str_ptr, fname.len()) };
                str_ptr = unsafe { str_ptr.add(fname.len()) };
                unsafe { *str_ptr = 0 };
                str_ptr = unsafe { str_ptr.add(1) };
                obj_fname_ptr
            } else {
                ptr::null()
            };

            unsafe {
                (*sym_ptr) = blazesym_sym_info {
                    name: name_ptr,
                    address,
                    size,
                    sym_type: match sym_type {
                        SymbolType::Function => blazesym_sym_type::SYM_T_FUNC,
                        SymbolType::Variable => blazesym_sym_type::SYM_T_VAR,
                        _ => blazesym_sym_type::SYM_T_UNKNOWN,
                    },
                    file_offset,
                    obj_file_name,
                }
            };
            sym_ptr = unsafe { sym_ptr.add(1) };
        }
        unsafe {
            (*sym_ptr) = blazesym_sym_info {
                name: ptr::null(),
                address: 0,
                size: 0,
                sym_type: blazesym_sym_type::SYM_T_UNKNOWN,
                file_offset: 0,
                obj_file_name: ptr::null(),
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };

        syms_ptr = unsafe { syms_ptr.add(1) };
    }

    raw_buf as *const *const blazesym_sym_info
}

/// Convert SymbolInfos returned by BlazeSymbolizer::find_address_regex() to a C array.
unsafe fn convert_syms_to_c(syms: Vec<SymbolInfo>) -> *const blazesym_sym_info {
    let mut str_buf_sz = 0;

    for sym in &syms {
        str_buf_sz += sym.name.len() + 1;
        if let Some(fname) = sym.obj_file_name.as_ref() {
            str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
        }
    }

    let sym_buf_sz = mem::size_of::<blazesym_sym_info>() * (syms.len() + 1);
    let buf_size = sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut sym_ptr = raw_buf as *mut blazesym_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(sym_buf_sz) } as *mut u8;

    for sym in syms {
        let SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } = sym;
        let name_ptr = str_ptr as *const u8;
        unsafe { ptr::copy_nonoverlapping(name.as_ptr(), str_ptr, name.len()) };
        str_ptr = unsafe { str_ptr.add(name.len()) };
        unsafe { *str_ptr = 0 };
        str_ptr = unsafe { str_ptr.add(1) };
        let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
            let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
            let obj_fname_ptr = str_ptr;
            unsafe { ptr::copy_nonoverlapping(fname.as_ptr(), str_ptr, fname.len()) };
            str_ptr = unsafe { str_ptr.add(fname.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            obj_fname_ptr
        } else {
            ptr::null()
        };

        unsafe {
            (*sym_ptr) = blazesym_sym_info {
                name: name_ptr,
                address,
                size,
                sym_type: match sym_type {
                    SymbolType::Function => blazesym_sym_type::SYM_T_FUNC,
                    SymbolType::Variable => blazesym_sym_type::SYM_T_VAR,
                    _ => blazesym_sym_type::SYM_T_UNKNOWN,
                },
                file_offset,
                obj_file_name,
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };
    }
    unsafe {
        (*sym_ptr) = blazesym_sym_info {
            name: ptr::null(),
            address: 0,
            size: 0,
            sym_type: blazesym_sym_type::SYM_T_UNKNOWN,
            file_offset: 0,
            obj_file_name: ptr::null(),
        }
    };

    raw_buf as *const blazesym_sym_info
}

/// The types of symbols.
///
/// This type is used to choice what type of symbols you like to find
/// and indicate the types of symbols found.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum blazesym_sym_type {
    /// Invalid type
    SYM_T_INVALID,
    /// You want to find a symbol of any type.
    SYM_T_UNKNOWN,
    /// The returned symbol is a function, or you want to find a function.
    SYM_T_FUNC,
    /// The returned symbol is a variable, or you want to find a variable.
    SYM_T_VAR,
}

/// Feature names of looking up addresses of symbols.
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum blazesym_faf_type {
    /// Invalid type
    FAF_T_INVALID,
    /// Return the offset in the file. (enable)
    FAF_T_OFFSET_IN_FILE,
    /// Return the file name of the shared object. (enable)
    FAF_T_OBJ_FILE_NAME,
    /// Return symbols having the given type. (sym_type)
    FAF_T_SYMBOL_TYPE,
}

/// The parameter parts of `blazesym_faddr_feature`.
#[repr(C)]
pub union blazesym_faf_param {
    enable: bool,
    sym_type: blazesym_sym_type,
}

/// Switches and settings of features of looking up addresses of
/// symbols.
///
/// See [`FindAddrFeature`] for details.
#[repr(C)]
pub struct blazesym_faddr_feature {
    ftype: blazesym_faf_type,
    param: blazesym_faf_param,
}

unsafe fn convert_find_addr_features(
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> Vec<FindAddrFeature> {
    let mut feature = features;
    let mut features_ret = vec![];
    for _ in 0..num_features {
        match unsafe { &(*feature).ftype } {
            blazesym_faf_type::FAF_T_SYMBOL_TYPE => {
                features_ret.push(match unsafe { (*feature).param.sym_type } {
                    blazesym_sym_type::SYM_T_UNKNOWN => {
                        FindAddrFeature::SymbolType(SymbolType::Unknown)
                    }
                    blazesym_sym_type::SYM_T_FUNC => {
                        FindAddrFeature::SymbolType(SymbolType::Function)
                    }
                    blazesym_sym_type::SYM_T_VAR => {
                        FindAddrFeature::SymbolType(SymbolType::Variable)
                    }
                    _ => {
                        panic!("Invalid symbol type");
                    }
                });
            }
            blazesym_faf_type::FAF_T_OFFSET_IN_FILE => {
                features_ret.push(FindAddrFeature::OffsetInFile(unsafe {
                    (*feature).param.enable
                }));
            }
            blazesym_faf_type::FAF_T_OBJ_FILE_NAME => {
                features_ret.push(FindAddrFeature::ObjFileName(unsafe {
                    (*feature).param.enable
                }));
            }
            _ => {
                panic!("Unknown find_address feature type");
            }
        }
        feature = unsafe { feature.add(1) };
    }

    features_ret
}

/// Find the addresses of symbols matching a pattern.
///
/// Return an array of `blazesym_sym_info` ending with an item having a null address.
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_free()`].
///
/// It works the same as [`blazesym_find_address_regex()`] with
/// additional controls on features.
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_address_regex_opt(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    pattern: *const c_char,
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> *const blazesym_sym_info {
    let sym_srcs_rs =
        if let Some(sym_srcs_rs) = unsafe { symbolsrccfg_to_rust(sym_srcs, sym_srcs_len) } {
            sym_srcs_rs
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to transform configurations of symbolizer from C to Rust");
            return ptr::null_mut();
        };

    let symbolizer = unsafe { &*(*symbolizer).symbolizer };

    let pattern = unsafe { CStr::from_ptr(pattern) };
    let features = unsafe { convert_find_addr_features(features, num_features) };
    let syms =
        { symbolizer.find_address_regex_opt(&sym_srcs_rs, pattern.to_str().unwrap(), features) };

    if syms.is_none() {
        return ptr::null_mut();
    }

    unsafe { convert_syms_to_c(syms.unwrap()) }
}

/// Find the addresses of symbols matching a pattern.
///
/// Return an array of `blazesym_sym_info` ending with an item having a null address.
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_free()`].
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_address_regex(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    pattern: *const c_char,
) -> *const blazesym_sym_info {
    unsafe {
        blazesym_find_address_regex_opt(symbolizer, sym_srcs, sym_srcs_len, pattern, ptr::null(), 0)
    }
}

/// Free an array returned by blazesym_find_addr_regex() or
/// blazesym_find_addr_regex_opt().
///
/// # Safety
///
/// The `syms` pointer should have been allocated by one of the
/// `blazesym_find_address*` variants.
#[no_mangle]
pub unsafe extern "C" fn blazesym_syms_free(syms: *const blazesym_sym_info) {
    if syms.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("blazesym_sym_info_free(null)");
        return;
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

/// Find the addresses of a list of symbols.
///
/// Return an array of `*const u64` with the same size as the
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_list_free()`].
///
/// Every name in the input name list may have more than one address.
/// The respective entry in the returned array is an array containing
/// all addresses and ended with a null (0x0).
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_list_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_addresses_opt(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    names: *const *const c_char,
    name_cnt: usize,
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> *const *const blazesym_sym_info {
    let sym_srcs_rs =
        if let Some(sym_srcs_rs) = unsafe { symbolsrccfg_to_rust(sym_srcs, sym_srcs_len) } {
            sym_srcs_rs
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to transform configurations of symbolizer from C to Rust");
            return ptr::null_mut();
        };

    let symbolizer = unsafe { &*(*symbolizer).symbolizer };

    let mut names_cstr = vec![];
    for i in 0..name_cnt {
        let name_c = unsafe { *names.add(i) };
        let name_r = unsafe { CStr::from_ptr(name_c) };
        names_cstr.push(name_r);
    }
    let features = unsafe { convert_find_addr_features(features, num_features) };
    let syms = {
        let mut names_r = vec![];
        for name in names_cstr.iter().take(name_cnt) {
            names_r.push(name.to_str().unwrap());
        }
        symbolizer.find_addresses_opt(&sym_srcs_rs, &names_r, features)
    };

    unsafe { convert_syms_list_to_c(syms) }
}

/// Find addresses of a symbol name.
///
/// A symbol may have multiple addressses.
///
/// # Safety
///
/// The returned data should be free by [`blazesym_syms_list_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_addresses(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    names: *const *const c_char,
    name_cnt: usize,
) -> *const *const blazesym_sym_info {
    unsafe {
        blazesym_find_addresses_opt(
            symbolizer,
            sym_srcs,
            sym_srcs_len,
            names,
            name_cnt,
            ptr::null(),
            0,
        )
    }
}

/// Free an array returned by blazesym_find_addresses.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_find_addresses()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_syms_list_free(syms_list: *const *const blazesym_sym_info) {
    if syms_list.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("blazesym_syms_list_free(null)");
        return;
    }

    let raw_buf_with_sz =
        unsafe { (syms_list as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

    #[test]
    fn hello_world_stack() {
        // A stack sample from a Hello World proram.
        let stack = vec![
            0xb0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xaf, 0x5, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xd0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xcb, 0x5, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let expected_rips = vec![0x000000000040058a, 0x00000000004005af, 0x00000000004005cb];
        let base = 0x7fffffffd5a0;
        let mut registers: [u64; 17] = [0; 17];

        registers[crate::REG_RIP] = expected_rips[0];
        registers[crate::REG_RBP] = 0x7fffffffd5a0;

        let mut session = crate::X86_64StackSession::new(stack, base, registers);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[0]);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[1]);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[2]);
    }

    #[test]
    fn load_symbolfilecfg_process() {
        // Check if SymbolSrcCfg::Process expands to ELFResolvers.
        let cfg = vec![SymbolSrcCfg::Process { pid: None }];
        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        });
        let resolver_map = ResolverMap::new(&cfg, &cache_holder);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
        // ElfResolver for the binary itself.
        assert!(signatures.iter().any(|x| x.contains("/blazesym")));
        // ElfResolver for libc.
        assert!(signatures.iter().any(|x| x.contains("/libc")));
    }

    #[test]
    fn load_symbolfilecfg_processkernel() {
        // Check if SymbolSrcCfg::Process & SymbolSrcCfg::Kernel expands to
        // ELFResolvers and a KernelResolver.
        let srcs = vec![
            SymbolSrcCfg::Process { pid: None },
            SymbolSrcCfg::Kernel {
                kallsyms: None,
                kernel_image: None,
            },
        ];
        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        });
        let resolver_map = ResolverMap::new(&srcs, &cache_holder);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
        // ElfResolver for the binary itself.
        assert!(signatures.iter().any(|x| x.contains("/blazesym")));
        // ElfResolver for libc.
        assert!(signatures.iter().any(|x| x.contains("/libc")));
        assert!(signatures.iter().any(|x| x.contains("KernelResolver")));
    }

    #[test]
    fn load_symbolfilecfg_invalid_kernel() {
        // Check if SymbolSrcCfg::Kernel expands to a KernelResolver
        // even if kernel_image is invalid.
        let srcs = vec![SymbolSrcCfg::Kernel {
            kallsyms: None,
            kernel_image: Some(PathBuf::from("/dev/null")),
        }];
        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        });
        let resolver_map = ResolverMap::new(&srcs, &cache_holder);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
        assert!(signatures.iter().any(|x| x.contains("KernelResolver")));

        let kallsyms = Path::new("/proc/kallsyms");
        let kernel_image = Path::new("/dev/null");
        let kresolver = KernelResolver::new(kallsyms, kernel_image, &cache_holder).unwrap();
        assert!(kresolver.ksymresolver.is_some());
        assert!(kresolver.kernelresolver.is_none());
    }

    #[test]
    fn load_gsym_resolver() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let test_gsym = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("test.gsym");
        let base: u64 = 0x77a7000; // pickup randomly.
        let features = vec![SymbolizerFeature::LineNumberInfo(true)];
        let srcs = vec![SymbolSrcCfg::Gsym {
            file_name: test_gsym,
            base_address: base,
        }];
        let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();
        // Check gsym-example.c for this hard-coded addresses
        let syms_lst = symbolizer.symbolize(&srcs, &[0x2020000 + base]);
        let mut cnt = 0;
        for syms in syms_lst {
            for sym in syms {
                assert_eq!(sym.symbol, "factorial");
                cnt += 1;
            }
        }
        assert_eq!(cnt, 1);
    }
}

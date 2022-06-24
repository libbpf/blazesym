// A library symbolizes addresses to symbols, filenames, and line numbers.
//
// BlazeSym is a library to symbolize addresses to get symbol names, file
// names of source files, and line numbers.  It can translate a stack
// trace to function names and their locations in the
// source code.
#![doc = include_str!("../README.md")]

use std::io::{Error, ErrorKind};
use std::u64;

use std::ffi::{CString, CStr};

use std::ptr;

use std::os::raw::c_char;
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::rc::Rc;

use nix::sys::utsname;
use nix::sys::stat::stat;

pub mod dwarf;
mod elf;
mod tools;
mod elf_cache;
mod ksym;

use ksym::{KSymResolver, KSymCache};
use elf_cache::{ElfBackend, ElfCache};

struct CacheHolder {
    ksym: KSymCache,
    elf: ElfCache,
}

impl CacheHolder {
    fn new() -> CacheHolder {
	CacheHolder {
	    ksym: ksym::KSymCache::new(),
	    elf: elf_cache::ElfCache::new(),
	}
    }

    fn get_ksym_cache(&self) -> &KSymCache {
	&self.ksym
    }

    fn get_elf_cache(&self) -> &ElfCache {
	&self.elf
    }
}

pub trait StackFrame {
    fn get_ip(&self) -> u64;
    fn get_frame_pointer(&self) -> u64;
}

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

/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e., a symbol file.
trait SymResolver {
    /// Return the range that this resolver serve in an address space.
    fn get_address_range(&self) -> (u64, u64);
    /// Find the name and the start address of a symbol found for
    /// the given address.
    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)>;
    /// Find the address of a symbol anme.
    fn find_address(&self, name: &str) -> Option<u64>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo>;

    fn repr(&self) -> String;
}

pub const REG_RAX: usize = 0;
pub const REG_RBX: usize = 1;
pub const REG_RCX: usize = 2;
pub const REG_RDX: usize = 3;
pub const REG_RSI: usize = 4;
pub const REG_RDI: usize = 5;
pub const REG_RSP: usize = 6;
pub const REG_RBP: usize = 7;
pub const REG_R8: usize = 8;
pub const REG_R9: usize = 9;
pub const REG_R10: usize = 10;
pub const REG_R11: usize = 11;
pub const REG_R12: usize = 12;
pub const REG_R13: usize = 13;
pub const REG_R14: usize = 14;
pub const REG_R15: usize = 15;
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
pub struct X86_64StackSession {
    frames: Vec<X86_64StackFrame>,
    stack: Vec<u8>,
    stack_base: u64,		// The base address of the stack
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
	(stack[off] as u64) |
	((stack[off + 1] as u64) << 8) |
	((stack[off + 2] as u64) << 16) |
	((stack[off + 3] as u64) << 24) |
	((stack[off + 4] as u64) << 32) |
	((stack[off + 5] as u64) << 40) |
	((stack[off + 6] as u64) << 48) |
	((stack[off + 7] as u64) << 56)
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
	    return None
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
pub unsafe extern "C" fn sym_resolver_create() -> *mut KSymResolver {
    let mut resolver = Box::new(KSymResolver::new());
    if resolver.load().is_err() {
	ptr::null_mut()
    } else {
	Box::leak(resolver)
    }
}

/// Free a KsymResolver
///
/// # Safety
///
/// The pointer passed in should be the one returned by
/// `sym_resolver_create()`.
///
#[no_mangle]
pub unsafe extern "C" fn sym_resolver_free(resolver_ptr: *mut KSymResolver) {
    Box::from_raw(resolver_ptr);
}

/// Find the symbols of a give address if there is.
///
/// # Safety
///
/// The returned string is managed by `resolver_ptr`.  Don't try to
/// free it.
///
#[no_mangle]
pub unsafe extern "C" fn sym_resolver_find_addr(resolver_ptr: *mut KSymResolver, addr: u64) -> *const c_char {
    let resolver = &*resolver_ptr;
    if let Some(sym) = resolver.find_address_ksym(addr) {
	let mut c_name = sym.c_name.borrow_mut();
	if c_name.is_none() {
	    *c_name = Some(CString::new(&sym.name as &str).unwrap());
	}
	return c_name.as_ref().unwrap().as_c_str().as_ptr();
    }
    ptr::null()
}

/// The symbol resolver for a single ELF file.
///
/// An ELF file may be loaded into an address space with a relocation.
/// The callers should provide the path of an ELF file and where it is
/// loaded.
///
/// For some ELF files, they are located at a specific address
/// determined during compile-time.  For these cases, just pass `0` as
/// it's loaded address.
struct ElfResolver {
    backend: ElfBackend,
    loaded_address: u64,
    offset: u64,
    size: u64,
    file_name: String,
}

impl ElfResolver {
    fn new(file_name: &str, loaded_address: u64, cache_holder: &CacheHolder) -> Result<ElfResolver, Error> {
	let backend = cache_holder.get_elf_cache().find(file_name)?;
	let parser = match &backend {
	    ElfBackend::Dwarf(dwarf) => dwarf.get_parser(),
	    ElfBackend::Elf(parser) => &*parser,
	};
	let e_type = parser.get_elf_file_type()?;
	let phdrs = parser.get_all_program_headers()?;

	// Find the size of the block where the ELF file is/was
	// mapped.
	let mut max_addr = 0;
	let mut low_addr = 0xffffffffffffffff;
	if e_type == elf::ET_DYN || e_type == elf::ET_EXEC {
	    for phdr in phdrs {
		if phdr.p_type != elf::PT_LOAD {
		    continue;
		}
		let end_at = phdr.p_vaddr + phdr.p_memsz;
		if max_addr < end_at {
		    max_addr = end_at;
		}
		if phdr.p_vaddr < low_addr {
		    low_addr = phdr.p_vaddr;
		}
	    }
	} else {
	    return Err(Error::new(ErrorKind::InvalidData, "unknown e_type"));
	}

	let loaded_address = loaded_address;
	let offset = low_addr;
	let size = if e_type == elf::ET_EXEC { max_addr - low_addr } else { max_addr };

	Ok(ElfResolver { backend, loaded_address, offset, size, file_name: file_name.to_string() })
    }

    fn get_parser(&self) -> Option<&elf::Elf64Parser> {
	match &self.backend {
	    ElfBackend::Dwarf(dwarf) => Some(dwarf.get_parser()),
	    ElfBackend::Elf(parser) => Some(&*parser),
	}
    }
}

impl SymResolver for ElfResolver {
    fn get_address_range(&self) -> (u64, u64) {
	(self.loaded_address, self.loaded_address + self.size)
    }

    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
	let off = addr - self.loaded_address + self.offset;
	let parser = self.get_parser()?;
	match parser.find_symbol(off, elf::STT_FUNC) {
	    Ok((name, start_addr)) => Some((name, start_addr + self.loaded_address)),
	    Err(_) => None,
	}
    }

    fn find_address(&self, _name: &str) -> Option<u64> {
	None
    }

    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
	let off = addr - self.loaded_address + self.offset;
	if let ElfBackend::Dwarf(dwarf) = &self.backend {
	    let (directory, file, line_no) = dwarf.find_line_as_ref(off)?;
	    let mut path = String::from(directory);
	    if !path.is_empty() && &path[(path.len() - 1)..] != "/" {
		path.push('/');
	    }
	    path.push_str(file);
	    Some(AddressLineInfo { path, line_no, column: 0 })
	} else {
	    None
	}
    }

    fn repr(&self) -> String {
	match self.backend {
	    ElfBackend::Dwarf(_) => format!("DWARF {}", self.file_name),
	    ElfBackend::Elf(_) => format!("ELF {}", self.file_name),
	}
    }
}

struct KernelResolver {
    ksymresolver: Rc<KSymResolver>,
    kernelresolver: ElfResolver,
    kallsyms: String,
    kernel_image: String,
}

impl KernelResolver {
    fn new(kallsyms: &str, kernel_image: &str, cache_holder: &CacheHolder) -> Result<KernelResolver, Error> {
	let ksymresolver = cache_holder.get_ksym_cache().get_resolver(kallsyms)?;
	let kernelresolver = ElfResolver::new(kernel_image, 0, cache_holder)?;
	Ok(KernelResolver {
	    ksymresolver,
	    kernelresolver,
	    kallsyms: kallsyms.to_string(),
	    kernel_image: kernel_image.to_string()
	})
    }
}

impl SymResolver for KernelResolver {
    fn get_address_range(&self) -> (u64, u64) {
	(0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
	self.ksymresolver.find_symbol(addr)
    }
    fn find_address(&self, _name: &str) -> Option<u64> {
	None
    }
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
	self.kernelresolver.find_line_info(addr)
    }

    fn repr(&self) -> String {
	format!("KernelResolver {} {}", self.kallsyms, self.kernel_image)
    }
}

/// The description of a source of symbols and debug info.
///
/// A source of symbols and debug info can be an ELF file, a kernel
/// image, or a process.
#[derive(Clone)]
pub enum SymbolFileCfg {
    /// A single ELF file
    ///
    /// You should give a file name of an ELF file and its loaded address.
    ///
    Elf {
	/// The file name of ELF files.
	///
	/// It can be a executable or a shared object.
	/// For example, Giving "/bin/sh" it will load symbols and debug info from it.
	/// Giving "/lib/libc.so.xxx", it will load symbols and debug info from the libc.
	file_name: String,
	/// The address where the file loaded.
	///
	/// It should be the address
	/// in the process mapping to the first byte of the file.
	/// For example, in /proc/&lt;pid&gt;/maps
	/// ```text
	///     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
	///     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
	///     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
	///     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
	/// ```
	/// It shows libc-2.28.so was loaded at 0x7fe1b2dc4000.  This
	/// address is used to translate an address in a process to the
	/// address, a relative offset, in the ELF file.
	loaded_address: u64,
    },
    /// Linux Kernel's binary image and a copy of /proc/kallsyms
    Kernel {
	/// A path of a copy of kallsyms.
	///
	/// It can be "/proc/kallsyms" for the running kernel on the
	/// device.  However, you can make a copy for later uses.  For
	/// that case, you should give the path of a copy.
	/// Giving None, by default, it will be "/proc/kallsyms".
	kallsyms: Option<String>,
	/// The path of a kernel image.
	///
	/// This should be the path of a kernel image.  For example,
	/// "/boot/vmlinux-xxxx".  For None, it will found the kernel
	/// image of the running kernel in "/boot/" or
	/// "/usr/lib/debug/boot/".
	kernel_image: Option<String>,
    },
    /// This one will be exapended into all ELF files loaded.
    Process { pid: Option<u32> },
}

/// The result of symbolization by BlazeSymbolizer.
///
/// [`BlazeSymbolizer::symbolize()`] returns a list of lists of `SymbolizedResult`.
/// It looks like `[[SymbolizedResult {...}, SymbolizedResult {...}, ...], [SymbolizedResult {...}, ...], ...]`.
/// Every entry at the first level is a list of `SymbolizedResult`.
/// It can return multiple results for an address since it can result from
/// several lines of code in different functions with inlining and
/// optimization by the compiler.
#[derive(Clone)]
pub struct SymbolizedResult {
    /// The symbol name that an address may belong to.
    pub symbol: String,
    /// The address where the symbol is located in the process.
    ///
    /// The address is in the target process, not the offset from the
    /// head of the shared object file.
    pub start_address: u64,
    /// The path of the source that defines the symbol.
    pub path: String,
    /// The line number of the symbolized instruction in the source code.
    ///
    /// This is the line number of the instruction of the address been
    /// symbolized, not the line number that define the symbol
    /// (function).
    pub line_no: usize,
    pub column: usize,
}

type ResolverList = Vec<((u64, u64), Box<dyn SymResolver>)>;

struct ResolverMap {
    resolvers: ResolverList,
}

impl ResolverMap {
    fn build_resolvers_proc_maps(pid: u32, resolvers: &mut ResolverList,
				 cache_holder: &CacheHolder) -> Result<(), Error> {
	let entries = tools::parse_maps(pid)?;
	let mut last_path = String::from("");

	for entry in entries.iter() {
	    if entry.offset != 0 {
		continue;
	    }
	    if &entry.path[..1] != "/" {
		continue;
	    }
	    if entry.path == last_path {
		continue;
	    }
	    last_path = entry.path.clone();

	    if let Ok(filestat) = stat(&entry.path[..]) {
		if (filestat.st_mode & 0o170000) != 0o100000 {
		    // Not a regular file
		    continue;
		}
	    } else {
		continue;
	    }
	    if let Ok(resolver) = ElfResolver::new(&entry.path, entry.loaded_address, cache_holder) {
		resolvers.push((resolver.get_address_range(), Box::new(resolver)));
	    } else {
		#[cfg(debug_assertions)]
		eprintln!("Fail to create ElfResolver for {}", entry.path);
	    }
	}

	Ok(())
    }

    pub fn new(sym_files: &[SymbolFileCfg], cache_holder: &CacheHolder) -> Result<ResolverMap, Error> {
	let mut resolvers = ResolverList::new();
	for cfg in sym_files {
	    match cfg {
		SymbolFileCfg::Elf { file_name, loaded_address } => {
		    let resolver = ElfResolver::new(file_name, *loaded_address, cache_holder)?;
		    resolvers.push((resolver.get_address_range(), Box::new(resolver)));
		},
		SymbolFileCfg::Kernel { kallsyms, kernel_image } => {
		    let kallsyms = if let Some(k) = kallsyms {
			k
		    } else {
			"/proc/kallsyms"
		    };
		    let kernel_image = if let Some(img) = kernel_image {
			img.clone()
		    } else {
			let release = utsname::uname()?.release().to_str().unwrap().to_string();
			let patterns = vec!["/boot/vmlinux-", "/usr/lib/debug/boot/vmlinux-"];
			let mut i = 0;
			let kernel_image = loop {
			    let path = format!("{}{}", patterns[i], release);
			    if stat(&path[..]).is_ok() {
				break path;
			    }
			    i += 1;
			    if i >= patterns.len() {
				break path;
			    }
			};
			kernel_image
		    };
		    if let Ok(resolver) = KernelResolver::new(kallsyms, &kernel_image, cache_holder) {
			resolvers.push((resolver.get_address_range(), Box::new(resolver)));
		    } else {
			#[cfg(debug_assertions)]
			eprintln!("fail to load the kernel image {}", kernel_image);
		    }
		},
		SymbolFileCfg::Process { pid } => {
		    let pid = if let Some(p) = pid {*p} else { 0 };

		    if let Err(_e) = Self::build_resolvers_proc_maps(pid, &mut resolvers, cache_holder) {
			#[cfg(debug_assertions)]
			eprintln!("Fail to load symbols for the process {}: {:?}", pid, _e);
		    }
		},
	    };
	}
	resolvers.sort_by_key(|x| (*x).0.0); // sorted by the loaded addresses

	Ok(ResolverMap { resolvers })
    }

    pub fn find_resolver(&self, address: u64) -> Option<&dyn SymResolver> {
	let idx =
	    tools::search_address_key(&self.resolvers,
				      address,
				      &|map: &((u64, u64), Box<dyn SymResolver>)| -> u64 { map.0.0 })?;
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

#[allow(dead_code)]
struct Symbol {
    pub name: String,
    pub addr: u64,
}

/// BlazeSymbolizer provides an interface to symbolize addresses with
/// a list of symbol sources.
///
/// Users should give BlazeSymbolizer a list of meta info of symbol
/// sources (`SymbolFileCfg`); for example, an ELF file and its loaded
/// location (`SymbolFileCfg::Elf`), or a Linux kernel image and a
/// copy of its kallsyms (`SymbolFileCfg::Kernel`).
///
pub struct BlazeSymbolizer {
    cache_holder: CacheHolder,
}

impl BlazeSymbolizer {
    /// Create and return an instance of BlazeSymbolizer.
    pub fn new() -> Result<BlazeSymbolizer, Error> {
	let cache_holder = CacheHolder::new();

	Ok(BlazeSymbolizer {
	    cache_holder,
	})
    }

    /// Find the address of a symbol.
    ///
    /// Not implemented yet!
    #[allow(dead_code)]
    fn find_address(&self, _cfg: &[SymbolFileCfg], _name: &str) -> Option<u64> {
	None
    }

    #[allow(dead_code)]
    fn find_line_info(&self, cfg: &[SymbolFileCfg], addr: u64) -> Option<AddressLineInfo> {
	let resolver_map = ResolverMap::new(cfg, &self.cache_holder).ok()?;
	let resolver = resolver_map.find_resolver(addr)?;
	resolver.find_line_info(addr)
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses with the information from the
    /// sources of symbols and debug info described by the slice
    /// (array) of SymbolFileCfg.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A list of symbol and debug sources.
    /// * `addresses` - A list of addresses been symbolized.
    pub fn symbolize(&self, cfg: &[SymbolFileCfg], addresses: &[u64]) -> Vec<Vec<SymbolizedResult>> {
	let resolver_map = if let Ok(map) = ResolverMap::new(cfg, &self.cache_holder){
	    map
	} else {
	    #[cfg(debug_assertions)]
	    eprintln!("Fail to build ResolverMap");
	    return vec![];
	};

	let info: Vec<Vec<SymbolizedResult>> =
	    addresses.iter().map(|addr| {
		let resolver = if let Some(resolver) = resolver_map.find_resolver(*addr) {
		    resolver
		} else {
		    return vec![];
		};

		let sym = resolver.find_symbol(*addr);
		let linfo = resolver.find_line_info(*addr);
		if sym.is_none() && linfo.is_none() {
		    vec![]
		} else if sym.is_none() {
		    let linfo = linfo.unwrap();
		    vec![SymbolizedResult {
			symbol: "".to_string(),
			start_address: 0,
			path: linfo.path,
			line_no: linfo.line_no,
			column: linfo.column,
		    }]
		} else if let Some(linfo) = linfo {
		    let (sym, start) = sym.unwrap();
		    vec![SymbolizedResult {
			symbol: String::from(sym),
			start_address: start,
			path: linfo.path,
			line_no: linfo.line_no,
			column: linfo.column,
		    }]
		} else {
		    let (sym, start) = sym.unwrap();
		    vec![SymbolizedResult {
			symbol: String::from(sym),
			start_address: start,
			path: "".to_string(),
			line_no: 0,
			column: 0,
		    }]
		}
	    }).collect();
	info
    }
}

/// Types of symbol sources and debug info for C API.
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum blazesym_cfg_type {
    /// Symbols and debug info from an ELF file
    CFG_T_ELF,
    /// Symbols and debug info from a kernel image and it's kallsyms
    CFG_T_KERNEL,
    /// Symbols and debug info from a process, including all object files loaded
    CFG_T_PROCESS,
}

/// Symbol File Configuration of ELF.
///
/// Describe the path and loaded address of an ELF file loaded in a
/// process.
#[repr(C)]
pub struct sfc_elf {
    /// The file name of ELF files.
    ///
    /// It can be an executable or a shared object.
    /// For example, giving "/bin/sh" will load symbols and debug info from it.
    /// Giving "/lib/libc.so.xxx", it will load symbols and debug info from the libc.
    pub file_name: *const c_char,
    /// The address where the file loaded.
    ///
    /// It should be the address
    /// in the process mapping to the first byte of the file.
    /// For example, in /proc/&lt;pid&gt;/maps
    /// ```text
    ///     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    /// ```
    /// It shows libc-2.28.so was loaded at 0x7fe1b2dc4000.  This
    /// address is used to translate an address in a process to the
    /// address, a relative offset, in the ELF file.
    pub loaded_address: u64,
}

/// Symbol File Configuration of Kernel.
///
/// Use a kernel image and a snapshot of its kallsyms as a symbol and
/// debug info source.
#[repr(C)]
pub struct sfc_kernel {
    /// A path of a copy of kallsyms.
    ///
    /// It can be "/proc/kallsyms" for the running kernel on the
    /// device.  However, you can make a copy for later uses.  For
    /// that case, you should give the path of a copy.
    /// Giving a NULL, by default, it will be "/proc/kallsyms".
    pub kallsyms: *const c_char,
    /// The path of a kernel image.
    ///
    /// This should be the path of a kernel image.  For example,
    /// "/boot/vmlinux-xxxx".  For a NULL value, it will find the
    /// kernel image of the running kernel in "/boot/" or
    /// "/usr/lib/debug/boot/".
    pub kernel_image: *const c_char,
}

/// Symbol File Configuration of a process.
///
/// Load all ELF files in a process as the sources of symbol and debug
/// info.
#[repr(C)]
pub struct sfc_process {
    /// PID of the process to symbolize.
    ///
    /// BlazeSym will parse /proc/&lt;pid&gt;/maps and load all object
    /// files in the process.
    pub pid: u32,
}

/// Parameters of symbol file configuratoin.
#[repr(C)]
pub union sfc_params {
    /// The variant for CFG_T_ELF
    pub elf: mem::ManuallyDrop<sfc_elf>,
    /// The variant for CFG_T_KERNEL
    pub kernel: mem::ManuallyDrop<sfc_kernel>,
    /// The variant for CFG_T_PROCESS
    pub process: mem::ManuallyDrop<sfc_process>,
}

/// A source of symbol information for C API.
#[repr(C)]
pub struct sym_file_cfg {
    /// The type of a source of symbols.
    pub cfg_type: blazesym_cfg_type,
    pub params: sfc_params,
}

/// A placeholder of symbolizer for C API.
///
/// It is returned from blazesym_new() and should be free by
/// blazesym_free().
#[repr(C)]
pub struct blazesym {
    symbolizer: *mut BlazeSymbolizer,
}

/// A symbolization result of an address for C API.
#[repr(C)]
pub struct blazesym_csym {
    /// The symbol name where the giving address may/should belong to.
    pub symbol: *const c_char,
    /// The address (the first byte) where the symbol located.
    ///
    /// It is the address already relocated to the address space of
    /// the process.
    pub start_address: u64,
    /// The path of the source code that defines the symbol.
    pub path: *const c_char,
    /// The line number in the source code where the instruction of the address is located.
    ///
    /// This is the line number of the instruction specified by the
    /// address been symbolized.
    pub line_no: usize,
    pub column: usize,
}

/// The collection of symbolization results of an address for C API.
///
/// Everny address has an entry to collect all symbols found by
/// BlazeSym.
#[repr(C)]
pub struct blazesym_entry {
    /// The number of symbols found for an address.
    pub size: usize,
    /// All symbols found.
    pub syms: *const blazesym_csym,
}

/// The collection of symbolization results of a list of addresses for C API.
///
/// The instances of blazesym_result are returned by
/// blazesym_symbolize().  They should be free by calling
/// blazesym_result_free().
#[repr(C)]
pub struct blazesym_result {
    //// The number of addresses being symbolized.
    pub size: usize,
    /// Symbolization results in the order of the list of
    /// symbolization addresses.
    ///
    /// Every address should have an entry here.
    pub entries: [blazesym_entry; 0],
}

/// Create a String from a pointer of C string
///
/// # Safety
///
/// Cstring should be terminated with a null byte.
///
unsafe fn from_cstr(cstr: *const c_char) -> String {
    CStr::from_ptr(cstr).to_str().unwrap().to_owned()
}

unsafe fn symbolfilecfg_to_rust(cfg: *const sym_file_cfg, cfg_len: u32) -> Option<Vec<SymbolFileCfg>> {
    let mut cfg_rs = Vec::<SymbolFileCfg>::with_capacity(cfg_len as usize);

    for i in 0..cfg_len {
	let c = cfg.offset(i as isize);
	match (*c).cfg_type {
	    blazesym_cfg_type::CFG_T_ELF => {
		cfg_rs.push(SymbolFileCfg::Elf {
		    file_name: from_cstr((*c).params.elf.file_name),
		    loaded_address: (*c).params.elf.loaded_address,
		});
	    },
	    blazesym_cfg_type::CFG_T_KERNEL => {
		let kallsyms = (*c).params.kernel.kallsyms;
		let kernel_image = (*c).params.kernel.kernel_image;
		cfg_rs.push(SymbolFileCfg::Kernel {
		    kallsyms: if !kallsyms.is_null() { Some(from_cstr(kallsyms)) } else { None },
		    kernel_image: if !kernel_image.is_null() { Some(from_cstr(kernel_image)) } else { None },
		});
	    },
	    blazesym_cfg_type::CFG_T_PROCESS => {
		cfg_rs.push(SymbolFileCfg::Process {
		    pid: if (*c).params.process.pid > 0 { Some((*c).params.process.pid) } else { None },
		});
	    },
	}
    }

    Some(cfg_rs)
}

/// Create an instance of blazesym (BlazeSymbolizer) for C API.
///
/// # Safety
///
/// Should free the pointer with blazesym_free.
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
    let c_box = Box::new(blazesym { symbolizer: Box::into_raw(symbolizer_box) });
    Box::into_raw(c_box)
}

/// Free an instance of blazesym (BlazeSymbolizer) for C API.
///
/// # Safety
///
/// The pointer must be returned by blazesym_new.
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_free(symbolizer: *mut blazesym) {
    if ! symbolizer.is_null() {
	Box::from_raw((*symbolizer).symbolizer);
	Box::from_raw(symbolizer);
    }
}

/// Convert SymbolizedResults to blazesym_results.
///
/// # Safety
///
/// The returned pointer should be freed by blazesym_result_free.
///
unsafe fn convert_symbolizedresults_to_c(results: Vec<Vec<SymbolizedResult>>) -> *const blazesym_result {
    // Allocate a buffer to contain a blazesym_result, all
    // blazesym_csym, and C strings of symbol and path.
    let strtab_size = results.iter().flatten().fold(0, |acc, result| {
	    acc + result.symbol.len() + result.path.len() + 2
    });
    let all_csym_size = results.iter().flatten().count();
    let buf_size = strtab_size + mem::size_of::<blazesym_result>() +
	mem::size_of::<blazesym_entry>() * results.len() +
	mem::size_of::<blazesym_csym>() * all_csym_size;
    let raw_buf_with_sz = alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap());

    // prepend an u64 to keep the size of the buffer.
    *(raw_buf_with_sz as *mut u64) = buf_size as u64;

    let raw_buf = raw_buf_with_sz.add(mem::size_of::<u64>());

    let result_ptr = raw_buf as *mut blazesym_result;
    let mut entry_last = &mut (*result_ptr).entries as *mut blazesym_entry;
    let mut csym_last = raw_buf.add(mem::size_of::<blazesym_result>() +
				    mem::size_of::<blazesym_entry>() * results.len()) as *mut blazesym_csym;
    let mut cstr_last = raw_buf.add(mem::size_of::<blazesym_result>() +
				    mem::size_of::<blazesym_entry>() * results.len() +
				    mem::size_of::<blazesym_csym>() * all_csym_size) as *mut c_char;

    let mut make_cstr = |src: &str| {
	let cstr = cstr_last;
	ptr::copy(src.as_ptr(), cstr as *mut u8, src.len());
	*cstr.add(src.len()) = 0;
	cstr_last = cstr_last.add(src.len() + 1);

	cstr
    };

    (*result_ptr).size = results.len();

    // Convert all SymbolizedResults to blazesym_entrys and blazesym_csyms
    for entry in results {
	(*entry_last).size = entry.len();
	(*entry_last).syms = csym_last;
	entry_last = entry_last.add(1);

	for r in entry {
	    let symbol_ptr = make_cstr(&r.symbol);

	    let path_ptr = make_cstr(&r.path);

	    let csym_ref = &mut *csym_last;
	    csym_ref.symbol = symbol_ptr;
	    csym_ref.start_address = r.start_address;
	    csym_ref.path = path_ptr;
	    csym_ref.line_no = r.line_no;
	    csym_ref.column = r.column;

	    csym_last = csym_last.add(1);
	}
    };

    result_ptr
}

/// Symbolize addresses with the debug info in symbol/debug files.
///
/// Return an array of blazesym_result with the same size as the
/// number of input addresses.  The caller should free the returned
/// array by calling `blazesym_result_free()`.
///
/// # Safety
///
/// The returned pointer should be freed by blazesym_result_free.
///
#[no_mangle]
pub unsafe extern "C"
fn blazesym_symbolize(symbolizer: *mut blazesym,
			     cfg: *const sym_file_cfg, cfg_len: u32,
			     addrs: *const u64,
			     addr_cnt: usize) -> *const blazesym_result {
    let cfg_rs = if let Some(cfg_rs) = symbolfilecfg_to_rust(cfg, cfg_len) {
	cfg_rs
    } else {
	#[cfg(debug_assertions)]
	eprintln!("Fail to transform configurations of symbolizer from C to Rust");
	return ptr::null_mut();
    };

    let symbolizer = &*(*symbolizer).symbolizer;
    let addresses = Vec::from_raw_parts(addrs as *mut u64, addr_cnt, addr_cnt);

    let results = symbolizer.symbolize(&cfg_rs, &addresses);

    addresses.leak();

    if results.is_empty() {
	#[cfg(debug_assertions)]
	eprintln!("Empty result while request for {}", addr_cnt);
	return ptr::null();
    }

    convert_symbolizedresults_to_c(results)
}

/// Free an array returned by blazesym_symbolize.
///
/// # Safety
///
/// The pointer must be returned by blazesym_symbolize.
///
#[no_mangle]
pub unsafe extern "C"
fn blazesym_result_free(results: *const blazesym_result) {
    if results.is_null() {
	#[cfg(debug_assertions)]
	eprintln!("blazesym_result_free(null)");
	return;
    }

    let raw_buf_with_sz = (results as *mut u8).offset(-(mem::size_of::<u64>() as isize));
    let sz = *(raw_buf_with_sz as *mut u64) as usize + mem::size_of::<u64>();
    dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_world_stack() {
	// A stack sample from a Hello World proram.
	let stack = vec![
	    0xb0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xaf, 0x5,
	    0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd0, 0xd5, 0xff, 0xff,
	    0xff, 0x7f, 0x0, 0x0, 0xcb, 0x5, 0x40, 0x0, 0x0, 0x0,
	    0x0, 0x0,
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
	// Check if SymbolFileCfg::Process expands to ELFResolvers.
	let cfg = vec![SymbolFileCfg::Process { pid: None }];
	let cache_holder = CacheHolder::new();
	let resolver_map = ResolverMap::new(&cfg, &cache_holder);
	assert!(resolver_map.is_ok());
	let resolver_map = resolver_map.unwrap();

	let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
	// ElfResolver for the binary itself.
	assert!(signatures.iter().find(|x| x.find("/blazesym").is_some()).is_some());
	// ElfResolver for libc.
	assert!(signatures.iter().find(|x| x.find("/libc").is_some()).is_some());
    }

    #[test]
    fn load_symbolfilecfg_processkernel() {
	// Check if SymbolFileCfg::Process & SymbolFileCfg::Kernel expands to
	// ELFResolvers and a KernelResolver.
	let cfg = vec![SymbolFileCfg::Process { pid: None }, SymbolFileCfg::Kernel { kallsyms: None, kernel_image: None }];
	let cache_holder = CacheHolder::new();
	let resolver_map = ResolverMap::new(&cfg, &cache_holder);
	assert!(resolver_map.is_ok());
	let resolver_map = resolver_map.unwrap();

	let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
	// ElfResolver for the binary itself.
	assert!(signatures.iter().find(|x| x.find("/blazesym").is_some()).is_some());
	// ElfResolver for libc.
	assert!(signatures.iter().find(|x| x.find("/libc").is_some()).is_some());
	assert!(signatures.iter().find(|x| x.find("KernelResolver").is_some()).is_some());
    }
}

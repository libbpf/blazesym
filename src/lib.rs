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

pub struct AddressLineInfo {
    pub path: String,
    pub line_no: usize,
    pub column: usize,
}

/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e., a symbol file.
pub trait SymResolver {
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

	let loaded_address = if e_type == elf::ET_EXEC { low_addr } else { loaded_address };
	let size = if e_type == elf::ET_EXEC { max_addr - low_addr } else { max_addr };

	Ok(ElfResolver { backend, loaded_address, size, file_name: file_name.to_string() })
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
	let off = addr - self.loaded_address;
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
	let off = addr - self.loaded_address;
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

/// The meta info of a symbol file.
#[derive(Clone)]
pub enum SymbolFileCfg {
    /// A single ELF file
    Elf { file_name: String, loaded_address: u64 },
    /// Linux Kernel's binary image and a copy of /proc/kallsyms
    Kernel { kallsyms: Option<String>, kernel_image: Option<String> },
    /// This one will be exapended into all ELF files loaded.
    Process { pid: Option<u32> },
}

/// The result of doing symbolization by BlazeSymbolizer.
#[derive(Clone)]
pub struct SymbolizedResult {
    pub symbol: String,
    pub start_address: u64,
    pub path: String,
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
	for entry in entries.iter() {
	    if entry.offset != 0 {
		continue;
	    }
	    if &entry.path[..1] != "/" {
		continue;
	    }
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
		eprintln!("Fail to ceate ElfResolver for {}", entry.path);
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

pub struct Symbol {
    pub name: String,
    pub addr: u64,
}

/// BlazeSymbolizer provides an interface to symbolize addresses with
/// a list of symbol files.
///
/// Users should give BlazeSymbolizer a list of meta info of symbol
/// files (`SymbolFileCfg`); for example, an ELF file and its loaded
/// location (`SymbolFileCfg::Elf`), or Linux kernel image and a copy
/// of its kallsyms (`SymbolFileCfg::Kernel`).
///
pub struct BlazeSymbolizer {
    cache_holder: CacheHolder,
}

impl BlazeSymbolizer {
    pub fn new() -> Result<BlazeSymbolizer, Error> {
	let cache_holder = CacheHolder::new();

	Ok(BlazeSymbolizer {
	    cache_holder,
	})
    }

    pub fn find_symbol(&self, cfg: &[SymbolFileCfg], addr: u64) -> Option<Symbol> {
	let resolver_map = ResolverMap::new(cfg, &self.cache_holder).ok()?;
	let resolver = resolver_map.find_resolver(addr)?;

	if let Some((sym, addr)) = resolver.find_symbol(addr) {
	    Some(Symbol { name: sym.to_string(), addr })
	} else {
	    None
	}
    }

    pub fn find_address(&self, _cfg: &[SymbolFileCfg], _name: &str) -> Option<u64> {
	None
    }

    pub fn find_line_info(&self, cfg: &[SymbolFileCfg], addr: u64) -> Option<AddressLineInfo> {
	let resolver_map = ResolverMap::new(cfg, &self.cache_holder).ok()?;
	let resolver = resolver_map.find_resolver(addr)?;
	resolver.find_line_info(addr)
    }

    pub fn symbolize(&self, cfg: &[SymbolFileCfg], addresses: &[u64]) -> Vec<Option<SymbolizedResult>> {
	let resolver_map = if let Ok(map) = ResolverMap::new(cfg, &self.cache_holder){
	    map
	} else {
	    #[cfg(debug_assertions)]
	    eprintln!("Fail to build ResolverMap");
	    return vec![];
	};

	let info: Vec<Option<SymbolizedResult>> =
	    addresses.iter().map(|addr| {
		let resolver = resolver_map.find_resolver(*addr)?;

		let sym = resolver.find_symbol(*addr);
		let linfo = resolver.find_line_info(*addr);
		if sym.is_none() && linfo.is_none() {
		    None
		} else if sym.is_none() {
		    let linfo = linfo.unwrap();
		    Some(SymbolizedResult {
			symbol: "".to_string(),
			start_address: 0,
			path: linfo.path,
			line_no: linfo.line_no,
			column: linfo.column,
		    })
		} else if let Some(linfo) = linfo {
		    let (sym, start) = sym.unwrap();
		    Some(SymbolizedResult {
			symbol: String::from(sym),
			start_address: start,
			path: linfo.path,
			line_no: linfo.line_no,
			column: linfo.column,
		    })
		} else {
		    let (sym, start) = sym.unwrap();
		    Some(SymbolizedResult {
			symbol: String::from(sym),
			start_address: start,
			path: "".to_string(),
			line_no: 0,
			column: 0,
		    })
		}
	    }).collect();
	info
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum blazesym_cfg_type {
    CFG_T_ELF,
    CFG_T_KERNEL,
    CFG_T_PROCESS,
}

#[repr(C)]
pub struct sfc_elf {
    file_name: *const c_char,
    loaded_address: u64,
}

#[repr(C)]
pub struct sfc_kernel {
    kallsyms: *const c_char,
    kernel_image: *const c_char,
}

#[repr(C)]
pub struct sfc_process {
    pid: u32,
}

#[repr(C)]
pub union sfc_params {
    elf: mem::ManuallyDrop<sfc_elf>,
    kernel: mem::ManuallyDrop<sfc_kernel>,
    process: mem::ManuallyDrop<sfc_process>,
}

#[repr(C)]
pub struct sym_file_cfg {
    cfg_type: blazesym_cfg_type,
    params: sfc_params,
}

#[repr(C)]
pub struct blazesym {
    symbolizer: *mut BlazeSymbolizer,
}

#[repr(C)]
pub struct blazesym_result {
    pub valid: bool,
    pub symbol: *const c_char,
    pub start_address: u64,
    pub path: *const c_char,
    pub line_no: usize,
    pub column: usize,
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

/// Create an instance of BlazeSymbolizer for C code.
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

/// Free an instance of BlazeSymbolizer.
///
/// # Safety
///
/// The pointer must be returned by blazesym_new.
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_free(symbolizer: *mut blazesym) {
    Box::from_raw((*symbolizer).symbolizer);
    Box::from_raw(symbolizer);
}

/// Convert SymbolizedResults to blazesym_results.
///
/// # Safety
///
/// The returned pointer should be freed by blazesym_result_free.
///
unsafe fn convert_symbolizedresults_to_c(results: Vec<Option<SymbolizedResult>>) -> *const blazesym_result {
    // Allocate a buffer to contain all blazesym_result and C
    // strings of symbol and path.
    let buf_sz = results.iter().fold(0, |acc, opt| {
	match opt {
	    Some(result) => {
		acc + result.symbol.len() + result.path.len() + 2
	    },
	    None => {
		acc
	    },
	}
    }) + 1 /* empty string */ + mem::size_of::<blazesym_result>() * results.len();
    let raw_buf_with_sz = alloc(Layout::from_size_align(buf_sz + mem::size_of::<u64>(), 8).unwrap());

    // prepend an u64 to keep the size of the buffer.
    *(raw_buf_with_sz as *mut u64) = buf_sz as u64;

    let raw_buf = raw_buf_with_sz.add(mem::size_of::<u64>());

    let mut rc_last = raw_buf as *mut blazesym_result;
    let mut cstr_last = raw_buf.add(mem::size_of::<blazesym_result>() * results.len()) as *mut c_char;

    let mut make_cstr = |src: &str| {
	let cstr = cstr_last;
	ptr::copy(src.as_ptr(), cstr as *mut u8, src.len());
	*cstr.add(src.len()) = 0;
	cstr_last = cstr_last.add(src.len() + 1);

	cstr
    };

    // Make an empty C string to use later
    let empty_cstr = make_cstr("");

    // Convert all SymbolizedResults to blazesym_results
    for opt in results {
	match opt {
	    Some(r) => {
		let symbol_ptr = make_cstr(&r.symbol);

		let path_ptr = make_cstr(&r.path);

		let rc_ref = &mut *rc_last;
		rc_ref.valid = true;
		rc_ref.symbol = symbol_ptr;
		rc_ref.start_address = r.start_address;
		rc_ref.path = path_ptr;
		rc_ref.line_no = r.line_no;
		rc_ref.column = r.column;

		rc_last = rc_last.add(1);
	    },
	    None => {
		let rc_ref = &mut *rc_last;
		rc_ref.valid = false;
		rc_ref.symbol = empty_cstr;
		rc_ref.start_address = 0;
		rc_ref.path = empty_cstr;
		rc_ref.line_no = 0;
		rc_ref.column =0;

		rc_last = rc_last.add(1);
	    },
	}
    };

    raw_buf as *const blazesym_result
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

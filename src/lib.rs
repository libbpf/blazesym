use std::io::{BufReader, BufRead, Error, ErrorKind};
use std::fs::File;
use std::u64;

use std::collections::HashMap;
use std::cell::RefCell;
use std::ptr;
use std::default::Default;

use std::ffi::CString;
use std::os::raw::c_char;


pub mod dwarf;
mod elf;
mod tools;

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

const KALLSYMS: &str = "/proc/kallsyms";
const DFL_KSYM_CAP: usize = 200000;

pub struct Ksym {
    addr: u64,
    name: String,
    c_name: RefCell<Option<CString>>,
}

/// The symbol resolver for /proc/kallsyms.
///
/// The users should provide the path of kallsyms, so you can provide
/// a copy from other devices.
pub struct KSymResolver {
    syms: Vec<Ksym>,
    sym_to_addr: RefCell<HashMap<&'static str, u64>>,
}

impl KSymResolver {
    pub fn new() -> KSymResolver {
	Default::default()
    }

    pub fn load_file_name(&mut self, filename: &str) -> Result<(), std::io::Error> {
	let f = File::open(filename)?;
	let mut reader = BufReader::new(f);
	let mut line = String::new();

	while let Ok(sz) = reader.read_line(&mut line) {
	    if sz == 0 {
		break;
	    }
	    let tokens: Vec<&str> = line.split_whitespace().collect();
	    if tokens.len() < 3 {
		break;
	    }
	    let (addr, _symbol, func) = (tokens[0], tokens[1], tokens[2]);
	    if let Ok(addr) = u64::from_str_radix(addr, 16) {
		let name = String::from(func);
		self.syms.push(Ksym { addr, name, c_name: RefCell::new(None) });
	    }

	    line.truncate(0);
	}

	self.syms.sort_by(|a, b| a.addr.cmp(&b.addr));

	Ok(())
    }

    pub fn load(&mut self) -> Result<(), std::io::Error> {
	self.load_file_name(KALLSYMS)
    }

    fn ensure_sym_to_addr(&self) {
	if self.sym_to_addr.borrow().len() > 0 {
	    return;
	}
	let mut sym_to_addr = self.sym_to_addr.borrow_mut();
	for Ksym { name, addr, c_name: _ } in self.syms.iter() {
	    // Performance & lifetime hacking
	    let name_static = unsafe { &*(name as *const String) };
	    sym_to_addr.insert(name_static, *addr);
	}
    }

    fn find_address_ksym(&self, addr: u64) -> Option<&Ksym> {
	let mut l = 0;
	let mut r = self.syms.len();

	if !self.syms.is_empty() && self.syms[0].addr > addr {
	    return None;
	}

	while l < (r - 1) {
	    let v = (l + r) / 2;
	    let sym = &self.syms[v];

	    if sym.addr == addr {
		return Some(sym);
	    }
	    if addr < sym.addr {
		r = v;
	    } else {
		l = v;
	    }
	}

	Some(&self.syms[l])
    }
}

impl Default for KSymResolver {
    fn default() -> Self {
	KSymResolver { syms: Vec::with_capacity(DFL_KSYM_CAP), sym_to_addr: RefCell::new(HashMap::new()) }
    }
}

impl SymResolver for KSymResolver {
    fn get_address_range(&self) -> (u64, u64) {
	(0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
	if let Some(sym) = self.find_address_ksym(addr) {
	    return Some((&sym.name, sym.addr));
	}
	None
    }

    fn find_address(&self, name: &str) -> Option<u64> {
	self.ensure_sym_to_addr();

	if let Some(addr) = self.sym_to_addr.borrow().get(name) {
	    return Some(*addr);
	}
	None
    }

    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
	None
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
    dwarf: dwarf::DwarfResolver,
    loaded_address: u64,
    size: u64,
}

impl ElfResolver {
    fn new(file_name: &str, loaded_address: u64) -> Result<ElfResolver, Error> {
	let parser = elf::Elf64Parser::open(file_name)?;
	let e_type = parser.get_elf_file_type()?;
	let phdrs = parser.get_all_program_headers()?;

	/// Find the size of the block where the ELF file is/was
	/// mapped.
	let mut max_addr = 0;
	if e_type == elf::ET_DYN || e_type == elf::ET_EXEC {
	    for phdr in phdrs {
		if phdr.p_type != elf::PT_LOAD {
		    continue;
		}
		let end_at = phdr.p_vaddr + phdr.p_memsz;
		if max_addr < end_at {
		    max_addr = end_at;
		}
	    }
	}

	let dwarf = dwarf::DwarfResolver::from_parser_for_addresses(parser, &[])?;

	Ok(ElfResolver { dwarf, loaded_address, size: max_addr })
    }
}

impl SymResolver for ElfResolver {
    fn get_address_range(&self) -> (u64, u64) {
	(self.loaded_address, self.loaded_address + self.size)
    }

    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
	let off = addr - self.loaded_address;
	let parser = self.dwarf.get_parser();
	match parser.find_symbol(addr, elf::STT_FUNC) {
	    Ok((name, start_addr)) => Some((name, start_addr)),
	    Err(_) => None,
	}
    }

    fn find_address(&self, name: &str) -> Option<u64> {
	None
    }

    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
	let off = addr - self.loaded_address;
	let (directory, file, line_no) = self.dwarf.find_line_as_ref(off)?;
	let mut path = String::from(directory);
	if !path.is_empty() && &path[(path.len() - 1)..] != "/" {
	    path.push('/');
	}
	path.push_str(file);
	Some(AddressLineInfo { path, line_no, column: 0 })
    }
}

struct LinuxKernelResolver {
    ksymresolver: KSymResolver,
    kernelresolver: ElfResolver,
}

impl LinuxKernelResolver {
    fn new(kallsyms: &str, kernel_image: &str) -> Result<LinuxKernelResolver, Error> {
	let mut ksymresolver = KSymResolver::new();
	ksymresolver.load_file_name(kallsyms)?;
	let kernelresolver = ElfResolver::new(kernel_image, 0)?;
	Ok(LinuxKernelResolver { ksymresolver, kernelresolver})
    }
}

impl SymResolver for LinuxKernelResolver {
    fn get_address_range(&self) -> (u64, u64) {
	(0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
	self.ksymresolver.find_symbol(addr)
    }
    fn find_address(&self, name: &str) -> Option<u64> {
	None
    }
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
	self.kernelresolver.find_line_info(addr)
    }
}

/// The meta info of a symbol file.
#[derive(Clone)]
pub enum SymbolFileCfg {
    /// A single ELF file
    Elf { file_name: String, loaded_address: u64 },
    /// Linux Kernel's binary image and a copy of /proc/kallsyms
    LinuxKernel { kallsyms: String, kernel_image: String },
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

/// BlazeSymbolizer provides an interface to symbolize addresses with
/// a list of symbol files.
///
/// Users should give BlazeSymbolizer a list of meta info of symbol
/// files (`SymbolFileCfg`); for example, an ELF file and its loaded
/// location (`SymbolFileCfg::Elf`), or Linux kernel image and a copy
/// of its kallsyms (`SymbolFileCfg::LinuxKernel`).
///
pub struct BlazeSymbolizer {
    sym_files: Vec<SymbolFileCfg>,
    resolver_map: Vec<((u64, u64), Box<dyn SymResolver>)>,
}

impl BlazeSymbolizer {
    pub fn new(sym_files: &[SymbolFileCfg]) -> Result<BlazeSymbolizer, Error> {
	let mut resolvers = Vec::<((u64, u64), Box<dyn SymResolver>)>::new();
	for cfg in sym_files {
	    let resolver: Box<dyn SymResolver> = match cfg {
		SymbolFileCfg::Elf { file_name, loaded_address } => {
		    let mut resolver = ElfResolver::new(&file_name, *loaded_address)?;
		    Box::new(resolver)
		},
		SymbolFileCfg::LinuxKernel { kallsyms, kernel_image } => {
		    let mut resolver = LinuxKernelResolver::new(&kallsyms, &kernel_image)?;
		    Box::new(resolver)
		},
	    };
	    resolvers.push((resolver.get_address_range(), resolver));
	}
	resolvers.sort_by_key(|x| (*x).0.0); // sorted by the loaded addresses

	Ok(BlazeSymbolizer {
	    sym_files: Vec::from(sym_files),
	    resolver_map: resolvers,
	})
    }

    fn find_resolver(&self, address: u64) -> Option<&dyn SymResolver> {
	let idx =
	    tools::search_address_key(&self.resolver_map,
				      address,
				      &|map: &((u64, u64), Box<dyn SymResolver>)| -> u64 { map.0.0 })?;
	let (loaded_begin, loaded_end) = self.resolver_map[idx].0;
	if loaded_begin != loaded_end && address >= loaded_end {
	    // `begin == end` means this ELF file may have only
	    // symbols and debug information.  For this case, we
	    // always use this resolver if the given address is just
	    // above its loaded address.
	    None
	} else {
	    Some(self.resolver_map[idx].1.as_ref())
	}
    }

    pub fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
	let resolver = self.find_resolver(addr)?;
	resolver.find_symbol(addr)
    }

    pub fn find_address(&self, name: &str) -> Option<u64> {
	None
    }

    pub fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
	let resolver = self.find_resolver(addr)?;
	resolver.find_line_info(addr)
    }

    pub fn symbolize(&self, addresses: &[u64]) -> Vec<Option<SymbolizedResult>> {
	let info: Vec<Option<SymbolizedResult>> =
	    addresses.iter().map(|addr| {
		let sym = self.find_symbol(*addr);
		let linfo = self.find_line_info(*addr);
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
		} else if linfo.is_none() {
		    let (sym, start) = sym.unwrap();
		    Some(SymbolizedResult {
			symbol: String::from(sym),
			start_address: start,
			path: "".to_string(),
			line_no: 0,
			column: 0,
		    })
		} else {
		    let (sym, start) = sym.unwrap();
		    let linfo = linfo.unwrap();
		    Some(SymbolizedResult {
			symbol: String::from(sym),
			start_address: start,
			path: linfo.path,
			line_no: linfo.line_no,
			column: linfo.column,
		    })
		}
	    }).collect();
	info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ksym_resolver_load_find() {
	let mut resolver = KSymResolver::new();
	assert!(resolver.load().is_ok());

	assert!(resolver.syms.len() > 100000);

	// Find the address of the symbol placed at the middle
	let sym = &resolver.syms[resolver.syms.len() / 2];
	let addr = sym.addr;
	let name = sym.name.clone();
	let found = resolver.find_symbol(addr);
	assert!(found.is_some());
	assert_eq!(found.unwrap().0, &name);
    	let addr = addr + 1;
	let found = resolver.find_symbol(addr);
	assert!(found.is_some());
	assert_eq!(found.unwrap().0, &name);

	// Find the address of the first symbol
	let found = resolver.find_symbol(0);
	assert!(found.is_some());

	// Find the address of the last symbol
	let sym = &resolver.syms.last().unwrap();
	let addr = sym.addr;
	let name = sym.name.clone();
	let found = resolver.find_symbol(addr);
	assert!(found.is_some());
	assert_eq!(found.unwrap().0, &name);
	let found = resolver.find_symbol(addr + 1);
	assert!(found.is_some());
	assert_eq!(found.unwrap().0, &name);

	// Find the symbol placed at the middle
	let sym = &resolver.syms[resolver.syms.len() / 2];
	let addr = sym.addr;
	let name = sym.name.clone();
	let found = resolver.find_address(&name);
	assert!(found.is_some());
	assert_eq!(found.unwrap(), addr);
    }

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
}

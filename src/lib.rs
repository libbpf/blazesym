use std::io::{BufReader, BufRead};
use std::fs::File;
use std::u64;

use std::collections::HashMap;
use std::cell::RefCell;
use std::ptr;

use std::ffi::CString;
use std::os::raw::c_char;

pub trait StackFrame {
    fn get_ip(&self) -> u64;
    fn get_frame_pointer(&self) -> u64;
}

pub trait StackSession {
    fn next_frame(&mut self) -> Option<&dyn StackFrame>;
    fn prev_frame(&mut self) -> Option<&dyn StackFrame>;
    fn go_top(&mut self);
}

pub trait SymResolver {
    fn find_address(&self, addr: u64) -> Option<&str>;
    fn find_symbol(&self, name: &str) -> Option<u64>;
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
    frames: Vec<Box<X86_64StackFrame>>,
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
	return (stack[off] as u64) |
	((stack[off + 1] as u64) << 8) |
	((stack[off + 2] as u64) << 16) |
	((stack[off + 3] as u64) << 24) |
	((stack[off + 4] as u64) << 32) |
	((stack[off + 5] as u64) << 40) |
	((stack[off + 6] as u64) << 48) |
	((stack[off + 7] as u64) << 56);
    }

    pub fn new(stack: Vec<u8>, stack_base: u64, registers: [u64; 17]) -> X86_64StackSession {
	X86_64StackSession {
	    frames: Vec::new(),
	    stack: stack,
	    stack_base: stack_base,
	    registers: registers,
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
	    let frame = &*self.frames[self.current_frame_idx];
	    self.current_frame_idx += 1;
	    return Some(frame);
	}

	let frame = X86_64StackFrame {
	    rip: self.current_rip,
	    rbp: self.current_rbp,
	};
	self.frames.push(Box::new(frame));

	if self._get_rbp_rel() <= (self.stack.len() - 16) {
	    let new_rbp = self._get_u64(self._get_rbp_rel());
	    let new_rip = self._get_u64(self._get_rbp_rel() + 8);
	    self.current_rbp = new_rbp;
	    self.current_rip = new_rip;
	} else {
	    self._mark_at_bottom();
	}

	self.current_frame_idx += 1;
	Some(&**self.frames.last().unwrap())
    }

    fn prev_frame(&mut self) -> Option<&dyn StackFrame> {
	if self.current_frame_idx == 0 {
	    return None
	}

	self.current_frame_idx -= 1;
	return Some(&*self.frames[self.current_frame_idx])
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

pub struct KSymResolver {
    syms: Vec<Ksym>,
    sym_to_addr: RefCell<HashMap<&'static str, u64>>,
}

impl KSymResolver {
    pub fn new() -> KSymResolver {
	KSymResolver { syms: Vec::with_capacity(DFL_KSYM_CAP), sym_to_addr: RefCell::new(HashMap::new()) }
    }

    pub fn load(&mut self) -> Result<(), std::io::Error> {
	let f = File::open(KALLSYMS)?;
	let mut reader = BufReader::new(f);
	let mut line = String::new();

	while let Ok(sz) = reader.read_line(&mut line) {
	    if sz <= 0 {
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

	if self.syms.len() > 0 && self.syms[0].addr > addr {
	    return None;
	}

	while l < (r - 1) {
	    let v = (l + r) / 2;
	    let sym = &self.syms[v];

	    if sym.addr == addr {
		return Some(&sym);
	    }
	    if addr < sym.addr {
		r = v;
	    } else {
		l = v;
	    }
	}

	return Some(&self.syms[l]);
    }
}

impl SymResolver for KSymResolver {
    fn find_address(&self, addr: u64) -> Option<&str> {
	if let Some(sym) = self.find_address_ksym(addr) {
	    return Some(&sym.name);
	}
	None
    }

    fn find_symbol(&self, name: &str) -> Option<u64> {
	self.ensure_sym_to_addr();

	if let Some(addr) = self.sym_to_addr.borrow().get(name) {
	    return Some(*addr);
	}
	None
    }
}

#[no_mangle]
pub extern "C" fn sym_resolver_create() -> *mut KSymResolver {
    let mut resolver = Box::new(KSymResolver::new());
    if let Err(_) = resolver.load() {
	return ptr::null_mut();
    }
    return Box::leak(resolver);
}

#[no_mangle]
pub extern "C" fn sym_resolver_free(resolver_ptr: *mut KSymResolver) {
    unsafe { Box::from_raw(resolver_ptr) };
}

#[no_mangle]
pub extern "C" fn sym_resolver_find_addr(resolver_ptr: *mut KSymResolver, addr: u64) -> *const c_char {
    let resolver = unsafe { &*resolver_ptr };
    if let Some(sym) = resolver.find_address_ksym(addr) {
	let mut c_name = sym.c_name.borrow_mut();
	if c_name.is_none() {
	    *c_name = Some(CString::new(&sym.name as &str).unwrap());
	}
	return c_name.as_ref().unwrap().as_c_str().as_ptr();
    }
    ptr::null()
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
	let found = resolver.find_address(addr);
	assert!(found.is_some());
	assert_eq!(found.unwrap(), &name);
    	let addr = addr + 1;
	let found = resolver.find_address(addr);
	assert!(found.is_some());
	assert_eq!(found.unwrap(), &name);

	// Find the address of the first symbol
	let found = resolver.find_address(0);
	assert!(found.is_some());

	// Find the address of the last symbol
	let sym = &resolver.syms.last().unwrap();
	let addr = sym.addr;
	let name = sym.name.clone();
	let found = resolver.find_address(addr);
	assert!(found.is_some());
	assert_eq!(found.unwrap(), &name);
	let found = resolver.find_address(addr + 1);
	assert!(found.is_some());
	assert_eq!(found.unwrap(), &name);

	// Find the symbol placed at the middle
	let sym = &resolver.syms[resolver.syms.len() / 2];
	let addr = sym.addr;
	let name = sym.name.clone();
	let found = resolver.find_symbol(&name);
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

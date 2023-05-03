extern crate blazesym;

use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::SymbolizedResult;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use std::env;

fn show_usage() {
    let args: Vec<String> = env::args().collect();
    println!("Usage: {} <pid> <address>", args[0]);
    println!("Resolve an address in the process of the given pid, and");
    println!("print its symbol, the file name of the source, and the line number.");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        show_usage();
        return
    }

    let pid = args[1].parse::<u32>().unwrap();
    let mut addr_str = &args[2][..];
    println!("PID: {pid}");

    if addr_str.len() > 2 && &addr_str[0..2] == "0x" {
        // Remove prefixed 0x
        addr_str = &addr_str[2..];
    }
    let addr = Addr::from_str_radix(addr_str, 16).unwrap();

    let src = Source::Process(Process::new(pid.into()));
    let resolver = Symbolizer::new().unwrap();
    let symlist = resolver.symbolize(&src, &[addr]).unwrap();
    if !symlist[0].is_empty() {
        let SymbolizedResult {
            symbol,
            addr: sym_addr,
            path,
            line,
            column: _,
        } = &symlist[0][0];
        println!(
            "0x{addr:x} {symbol}@0x{addr:x}+{} {}:{line}",
            addr - sym_addr,
            path.display(),
        );
    } else {
        println!("0x{addr:x} is not found");
    }
}

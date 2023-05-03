extern crate blazesym;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use std::env;
use std::path;

fn show_usage() {
    let args: Vec<String> = env::args().collect();
    println!("Usage: {} <file> <address>", args[0]);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        show_usage();
        return
    }

    let bin_name = &args[1];
    let mut addr_str = &args[2][..];
    let src = Source::Elf(Elf {
        file_name: path::PathBuf::from(bin_name),
        base_address: 0x0,
    });
    let resolver = Symbolizer::new().unwrap();

    if &addr_str[0..2] == "0x" {
        // Remove prefixed 0x
        addr_str = &addr_str[2..];
    }
    let addr = Addr::from_str_radix(addr_str, 16).unwrap();

    let results = resolver.symbolize(&src, &[addr]).unwrap();
    if results.len() == 1 && !results[0].is_empty() {
        let result = &results[0][0];
        println!(
            "0x{addr:x} @ {} {}:{}",
            result.symbol,
            result.path.display(),
            result.line
        );
    } else {
        println!("0x{addr:x} is not found");
    }
}

use std::env;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        bail!(
            "Usage: {} <elf-path> <address>",
            args.first().map(String::as_str).unwrap_or("addr2ln_pid")
        );
    }

    let bin_name = &args[1];
    let addr_str = &args[2][..];
    let src = Source::Elf(Elf::new(bin_name));
    let symbolizer = Symbolizer::new();

    let addr = Addr::from_str_radix(addr_str.trim_start_matches("0x"), 16)
        .with_context(|| format!("failed to parse address: {addr_str}"))?;

    let syms = symbolizer
        .symbolize(&src, &[addr])
        .with_context(|| format!("failed to symbolize address 0x{addr:x}"))?;

    for (addr, syms) in [addr].iter().zip(syms) {
        let mut addr_fmt = format!("0x{addr:016x}:");
        if syms.is_empty() {
            println!("{addr_fmt} <no-symbol>")
        } else {
            for (i, sym) in syms.into_iter().enumerate() {
                if i == 1 {
                    addr_fmt = addr_fmt.replace(|_c| true, " ");
                }

                let Sym {
                    name, addr, offset, ..
                } = sym;

                let src_loc = if let (Some(path), Some(line)) = (sym.path, sym.line) {
                    if let Some(col) = sym.column {
                        format!(" {}:{line}:{col}", path.display())
                    } else {
                        format!(" {}:{line}", path.display())
                    }
                } else {
                    String::new()
                };

                println!("{addr_fmt} {name} @ 0x{addr:x}+0x{offset:x}{src_loc}");
            }
        }
    }
    Ok(())
}

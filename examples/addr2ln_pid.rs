use std::env;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        bail!(
            "Usage: {} <pid> <address>
Resolve an address in the process of the given pid, and
print its symbol, the file name of the source, and the line number.",
            args.first().map(String::as_str).unwrap_or("addr2ln_pid")
        );
    }

    let pid = args[1].parse::<u32>().unwrap();
    let addr_str = &args[2][..];
    println!("PID: {pid}");

    let addr = Addr::from_str_radix(addr_str.trim_start_matches("0x"), 16)
        .with_context(|| format!("failed to parse address: {addr_str}"))?;

    let src = Source::Process(Process::new(pid.into()));
    let symbolizer = Symbolizer::new();
    let syms = symbolizer
        .symbolize(&src, &[addr])
        .with_context(|| format!("failed to symbolize address 0x{addr:x}"))?;

    for (addr, syms) in [addr].into_iter().zip(syms) {
        let mut addr_fmt = format!("0x{addr:016x}:");
        if syms.is_empty() {
            println!("{addr_fmt} <no-symbol>")
        } else {
            for (i, sym) in syms.into_iter().enumerate() {
                if i == 1 {
                    addr_fmt = addr_fmt.replace(|_c| true, " ");
                }

                let Sym {
                    name,
                    addr: sym_addr,
                    path,
                    line,
                    ..
                } = sym;

                println!(
                    "{addr_fmt} {name} @ 0x{sym_addr:x}+0x{:x} {}:{line}",
                    addr - sym_addr,
                    path.display(),
                );
            }
        }
    }

    Ok(())
}

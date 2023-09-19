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
    let addrs = [addr];
    let symbolizer = Symbolizer::new();
    let syms = symbolizer
        .symbolize(&src, &addrs)
        .with_context(|| format!("failed to symbolize address {addr:#x}"))?;

    let addr_width = 16;
    let mut prev_addr_idx = None;

    for (sym, addr_idx) in syms {
        if let Some(idx) = prev_addr_idx {
            // Print a line for all addresses that did not get symbolized.
            for input_addr in addrs.iter().take(addr_idx).skip(idx + 1) {
                println!("{input_addr:#0width$x}: <no-symbol>", width = addr_width)
            }
        }

        let Sym {
            name,
            addr,
            offset,
            line,
            column,
            ..
        } = &sym;

        let src_loc = if let (Some(path), Some(line)) = (sym.to_path(), line) {
            if let Some(col) = column {
                format!(" {}:{line}:{col}", path.display())
            } else {
                format!(" {}:{line}", path.display())
            }
        } else {
            String::new()
        };

        if prev_addr_idx != Some(addr_idx) {
            // If the address index changed we reached a new symbol.
            println!(
                "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{src_loc}",
                input_addr = addrs[addr_idx],
                width = addr_width
            );
        } else {
            // Otherwise we are dealing with an inlined call.
            println!(
                "{:width$}  {name} @ {addr:#x}+{offset:#x}{src_loc}",
                " ",
                width = addr_width
            );
        }

        prev_addr_idx = Some(addr_idx);
    }
    Ok(())
}

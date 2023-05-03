use std::env;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        bail!(
            "Usage: {} <pid> <address>",
            args.first().map(String::as_str).unwrap_or("addr2ln_pid")
        );
    }

    let bin_name = &args[1];
    let mut addr_str = &args[2][..];
    let src = Source::Elf(Elf::new(bin_name));
    let resolver = Symbolizer::new().unwrap();

    if &addr_str[0..2] == "0x" {
        // Remove prefixed 0x
        addr_str = &addr_str[2..];
    }
    let addr = Addr::from_str_radix(addr_str, 16)
        .with_context(|| format!("failed to parse address: {addr_str}"))?;

    let results = resolver
        .symbolize(&src, &[addr])
        .with_context(|| format!("failed to symbolize address {addr}"))?;
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

    Ok(())
}

#![allow(clippy::let_and_return, clippy::let_unit_value)]

mod args;

use anyhow::Context;
use anyhow::Result;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolizer;

use clap::Parser as _;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;


/// The handler for the 'symbolize' command.
fn symbolize(symbolize: args::Symbolize) -> Result<()> {
    let symbolizer = Symbolizer::new();
    let (src, addrs) = match symbolize {
        args::Symbolize::Elf(args::Elf { path, addrs }) => {
            let src = Source::from(Elf::new(path));
            (src, addrs)
        }
        args::Symbolize::Process(args::Process { pid, addrs }) => {
            let src = Source::from(Process::new(pid));
            (src, addrs)
        }
    };

    let syms = symbolizer
        .symbolize(&src, &addrs)
        .context("failed to symbolize addresses")?;

    for (addr, syms) in addrs.into_iter().zip(syms) {
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
                    offset,
                    path,
                    line,
                    ..
                } = sym;

                println!(
                    "{addr_fmt} {name} @ 0x{sym_addr:x}+0x{offset:x} {}:{line}",
                    path.display(),
                );
            }
        }
    }
    Ok(())
}


fn main() -> Result<()> {
    let args = args::Args::parse();
    let level = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_span_events(FmtSpan::FULL)
        .with_timer(SystemTime)
        .finish();

    let () =
        set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;

    match args.command {
        args::Command::Symbolize(symbolize) => self::symbolize(symbolize),
    }
}

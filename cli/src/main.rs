#![allow(clippy::let_and_return, clippy::let_unit_value)]

mod args;

use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;

use blazesym::normalize;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;

use clap::Parser as _;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;


fn format_build_id_bytes(build_id: &[u8]) -> String {
    build_id
        .iter()
        .fold(String::with_capacity(build_id.len() * 2), |mut s, b| {
            let () = s.push_str(&format!("{b:02x}"));
            s
        })
}

fn format_build_id(build_id: Option<&[u8]>) -> String {
    if let Some(build_id) = build_id {
        format!(" (build ID: {})", format_build_id_bytes(build_id))
    } else {
        String::new()
    }
}

fn normalize(normalize: args::Normalize) -> Result<()> {
    let normalizer = Normalizer::new();
    match normalize {
        args::Normalize::User(args::User { pid, addrs }) => {
            let norm_addrs = normalizer
                .normalize_user_addrs(addrs.as_slice(), pid)
                .context("failed to normalize addresses")?;
            for (addr, (norm_addr, meta_idx)) in addrs.iter().zip(&norm_addrs.addrs) {
                print!("{addr:#016x}: ");

                let meta = &norm_addrs.meta[*meta_idx];
                match meta {
                    normalize::UserAddrMeta::ApkElf(normalize::ApkElf {
                        apk_path,
                        elf_path,
                        elf_build_id,
                        ..
                    }) => {
                        let build_id = format_build_id(elf_build_id.as_deref());
                        println!(
                            "{norm_addr:#x} @ {} in {}{build_id}",
                            elf_path.display(),
                            apk_path.display()
                        )
                    }
                    normalize::UserAddrMeta::Elf(normalize::Elf { path, build_id, .. }) => {
                        let build_id = format_build_id(build_id.as_deref());
                        println!("{norm_addr:#x} @ {}{build_id}", path.display())
                    }
                    normalize::UserAddrMeta::Unknown(normalize::Unknown { .. }) => {
                        println!("<unknown>")
                    }
                    // This is a bug and should be reported as such.
                    _ => panic!("encountered unsupported user address meta data: {meta:?}"),
                }
            }
        }
    }
    Ok(())
}

/// The handler for the 'symbolize' command.
fn symbolize(symbolize: args::Symbolize) -> Result<()> {
    let symbolizer = Symbolizer::new();
    let (src, addrs) = match symbolize {
        args::Symbolize::Elf(args::Elf { path, addrs }) => {
            let src = symbolize::Source::from(symbolize::Elf::new(path));
            (src, addrs)
        }
        args::Symbolize::Process(args::Process { pid, addrs }) => {
            let src = symbolize::Source::from(symbolize::Process::new(pid));
            (src, addrs)
        }
    };

    let syms = symbolizer
        .symbolize(&src, &addrs)
        .context("failed to symbolize addresses")?;

    for (addr, syms) in addrs.iter().zip(syms) {
        let mut addr_fmt = format!("{addr:#016x}:");
        if syms.is_empty() {
            println!("{addr_fmt} <no-symbol>")
        } else {
            for (i, sym) in syms.into_iter().enumerate() {
                if i == 1 {
                    addr_fmt = addr_fmt.replace(|_c| true, " ");
                }

                let symbolize::Sym {
                    name, addr, offset, ..
                } = sym;

                let path = match (sym.dir, sym.file) {
                    (Some(dir), Some(file)) => Some(dir.join(file)),
                    (dir, file) => dir.or_else(|| file.map(PathBuf::from)),
                };

                let src_loc = if let (Some(path), Some(line)) = (path, sym.line) {
                    if let Some(col) = sym.column {
                        format!(" {}:{line}:{col}", path.display())
                    } else {
                        format!(" {}:{line}", path.display())
                    }
                } else {
                    String::new()
                };

                println!("{addr_fmt} {name} @ {addr:#x}{offset:#x}{src_loc}");
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
        args::Command::Normalize(normalize) => self::normalize(normalize),
        args::Command::Symbolize(symbolize) => self::symbolize(symbolize),
    }
}

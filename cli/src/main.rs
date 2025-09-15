//! A command line utility for the `blazesym` library.

mod args;
mod trace;

use std::cmp::max;
use std::io::stderr;
use std::ops::ControlFlow;

use anyhow::Context;
use anyhow::Result;

use blazesym::helper::read_elf_build_id;
use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize;
use blazesym::normalize::NormalizeOpts;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::MaybeDefault;
use blazesym::SymType;

use clap::Parser as _;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing::Level;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Registry;

const ADDR_WIDTH: usize = 16;


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


fn print_sym_infos(sym_infos: &[inspect::SymInfo]) {
    let name_width = sym_infos
        .iter()
        .map(|sym| sym.name.len())
        .reduce(max)
        .map(|w| w + 1)
        .unwrap_or(0);
    for sym in sym_infos {
        let name = format!("{}:", sym.name);
        let addr = sym.addr;
        let size = sym.size;
        let type_ = match sym.sym_type {
            SymType::Function => " [FUNC]",
            SymType::Variable => " [VAR]",
            _ => " [UNDEF]",
        };
        println!(
            "{name:<name_width$} {addr:#0ADDR_WIDTH$x} {size:<11}{type_}",
            size = format!(
                "(size={})",
                size.map(|size| size.to_string())
                    .unwrap_or_else(|| "N/A".to_string())
            ),
        );
    }
}

fn inspect(inspect: args::inspect::Inspect) -> Result<()> {
    let inspector = Inspector::new();
    match inspect {
        args::inspect::Inspect::Lookup(lookup) => {
            let (src, names) = match lookup {
                args::inspect::Lookup::Breakpad(args::inspect::BreakpadLookup {
                    path,
                    ref names,
                }) => {
                    let src = inspect::source::Source::from(inspect::source::Breakpad::new(path));
                    (src, names)
                }
                args::inspect::Lookup::Elf(args::inspect::ElfLookup { path, ref names }) => {
                    let src = inspect::source::Source::from(inspect::source::Elf::new(path));
                    (src, names)
                }
            };

            let names = names.iter().map(AsRef::as_ref).collect::<Vec<&str>>();
            let result = inspector.lookup(&src, &names)?;
            let sym_infos = result
                .into_iter()
                .flat_map(|mut sym_infos| {
                    let () = sym_infos.sort_by_key(|sym| sym.addr);
                    sym_infos
                })
                .collect::<Vec<_>>();

            let () = print_sym_infos(&sym_infos);
            Ok(())
        }
        args::inspect::Inspect::Dump(dump) => {
            let src = match dump {
                args::inspect::Dump::Breakpad(args::inspect::BreakpadDump { path }) => {
                    inspect::source::Source::from(inspect::source::Breakpad::new(path))
                }
                args::inspect::Dump::Elf(args::inspect::ElfDump {
                    path,
                    no_debug_syms,
                }) => {
                    let mut elf = inspect::source::Elf::new(path);
                    elf.debug_syms = !no_debug_syms;
                    inspect::source::Source::from(elf)
                }
            };
            let mut sym_infos = Vec::new();
            let () = inspector.for_each(&src, |sym| {
                let () = sym_infos.push(sym.to_owned());
                ControlFlow::Continue(())
            })?;
            let () = sym_infos.sort_by_key(|sym| sym.addr);
            let () = print_sym_infos(&sym_infos);
            Ok(())
        }
        args::inspect::Inspect::BuildId(args::inspect::BuildId::Elf { path }) => {
            let build_id = read_elf_build_id(&path)?;
            if let Some(build_id) = build_id {
                println!("{}", format_build_id_bytes(&build_id));
            } else {
                println!("N/A");
            }
            Ok(())
        }
    }
}


fn normalize(normalize: args::normalize::Normalize) -> Result<()> {
    match normalize {
        args::normalize::Normalize::User(args::normalize::User {
            pid,
            addrs,
            no_build_ids,
            map_files,
            procmap_query,
        }) => {
            let normalizer = Normalizer::builder()
                .enable_build_ids(!no_build_ids)
                .enable_procmap_query(procmap_query)
                .build();
            let opts = NormalizeOpts {
                map_files,
                ..Default::default()
            };
            let normalized = normalizer
                .normalize_user_addrs_opts(pid, addrs.as_slice(), &opts)
                .context("failed to normalize addresses")?;
            for (addr, (output, meta_idx)) in addrs.iter().zip(&normalized.outputs) {
                print!("{addr:#016x}: ");

                let meta = &normalized.meta[*meta_idx];
                match meta {
                    normalize::UserMeta::Apk(normalize::Apk { path, .. }) => {
                        println!("file offset {output:#x} in {}", path.display())
                    }
                    normalize::UserMeta::Elf(normalize::Elf { path, build_id, .. }) => {
                        let build_id = format_build_id(build_id.as_deref());
                        println!("file offset {output:#x} in {}{build_id}", path.display())
                    }
                    normalize::UserMeta::Unknown(normalize::Unknown { .. }) => {
                        println!("<unknown>")
                    }
                    // This is a bug and should be reported as such.
                    _ => panic!("encountered unsupported user meta data: {meta:?}"),
                }
            }
        }
    }
    Ok(())
}

fn print_frame(
    name: &str,
    addr_info: Option<(Addr, Addr, usize)>,
    code_info: Option<&symbolize::CodeInfo>,
) {
    let code_info = code_info.map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        // If we have various address information bits we have a new symbol.
        println!(
            "{input_addr:#0ADDR_WIDTH$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or("")
        )
    } else {
        // Otherwise we are dealing with an inlined call.
        println!(
            "{:ADDR_WIDTH$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or("")
        )
    }
}

/// The handler for the 'symbolize' command.
fn symbolize(symbolize: args::symbolize::Symbolize) -> Result<()> {
    let mut builder = Symbolizer::builder();
    let (src, input, addrs) = match symbolize {
        args::symbolize::Symbolize::Breakpad(args::symbolize::Breakpad { path, ref addrs }) => {
            let src = symbolize::source::Source::from(symbolize::source::Breakpad::new(path));
            let addrs = addrs.as_slice();
            let input = symbolize::Input::FileOffset(addrs);
            (src, input, addrs)
        }
        args::symbolize::Symbolize::Elf(args::symbolize::Elf {
            path,
            debug_args:
                args::symbolize::DebugArgs {
                    debug_dirs,
                    no_debug_syms,
                },
            ref addrs,
        }) => {
            builder = builder.set_debug_dirs(debug_dirs);

            let mut elf = symbolize::source::Elf::new(path);
            elf.debug_syms = !no_debug_syms;
            let src = symbolize::source::Source::from(elf);
            let addrs = addrs.as_slice();
            let input = symbolize::Input::VirtOffset(addrs);
            (src, input, addrs)
        }
        args::symbolize::Symbolize::Gsym(args::symbolize::Gsym { path, ref addrs }) => {
            let src = symbolize::source::Source::from(symbolize::source::GsymFile::new(path));
            let addrs = addrs.as_slice();
            let input = symbolize::Input::VirtOffset(addrs);
            (src, input, addrs)
        }
        args::symbolize::Symbolize::Process(args::symbolize::Process {
            pid,
            debug_args:
                args::symbolize::DebugArgs {
                    debug_dirs,
                    no_debug_syms,
                },
            ref addrs,
            no_map_files,
        }) => {
            builder = builder.set_debug_dirs(debug_dirs);

            let mut process = symbolize::source::Process::new(pid);
            process.debug_syms = !no_debug_syms;
            process.map_files = !no_map_files;
            let src = symbolize::source::Source::from(process);
            let addrs = addrs.as_slice();
            let input = symbolize::Input::AbsAddr(addrs);
            (src, input, addrs)
        }
        args::symbolize::Symbolize::Kernel(args::symbolize::Kernel {
            kallsyms,
            vmlinux,
            ref addrs,
        }) => {
            let kernel = symbolize::source::Kernel {
                kallsyms: match kallsyms {
                    None => MaybeDefault::Default,
                    Some(path) if path.as_os_str().is_empty() => MaybeDefault::None,
                    Some(path) => MaybeDefault::Some(path.into()),
                },
                vmlinux: match vmlinux {
                    None => MaybeDefault::Default,
                    Some(path) if path.as_os_str().is_empty() => MaybeDefault::None,
                    Some(path) => MaybeDefault::Some(path.into()),
                },
                ..Default::default()
            };
            let src = symbolize::source::Source::from(kernel);
            let addrs = addrs.as_slice();
            let input = symbolize::Input::AbsAddr(addrs);
            (src, input, addrs)
        }
    };

    let symbolizer = builder.build();
    let syms = symbolizer
        .symbolize(&src, input)
        .context("failed to symbolize addresses")?;

    for (input_addr, sym) in addrs.iter().copied().zip(syms) {
        match sym {
            symbolize::Symbolized::Sym(symbolize::Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                print_frame(
                    &name,
                    Some((input_addr, addr, offset)),
                    code_info.as_deref(),
                );
                for frame in inlined.iter() {
                    print_frame(&frame.name, None, frame.code_info.as_ref());
                }
            }
            symbolize::Symbolized::Unknown(..) => {
                println!("{input_addr:#0ADDR_WIDTH$x}: <no-symbol>")
            }
        }
    }
    Ok(())
}


fn main() -> Result<()> {
    let args = args::Args::parse();
    let verbosity = match args.verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let hierarchical = trace::Hierarchical::builder()
        .with_max_verbosity(Some(verbosity))
        .with_time(Some(SystemTime))
        .build(stderr());
    let subscriber = Registry::default().with(hierarchical);
    let () =
        set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;

    match args.command {
        args::Command::Inspect(inspect) => self::inspect(inspect),
        args::Command::Normalize(normalize) => self::normalize(normalize),
        args::Command::Symbolize(symbolize) => self::symbolize(symbolize),
    }
}

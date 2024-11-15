#![allow(clippy::collapsible_if)]

use anyhow::Context as _;
use anyhow::Error;
use anyhow::Result;

use blazesym::helper::read_elf_build_id;
use blazesym::helper::ElfResolver;
use blazesym::symbolize;
use blazesym::symbolize::CodeInfo;
use blazesym::symbolize::Input;
use blazesym::symbolize::ProcessMemberInfo;
use blazesym::symbolize::ProcessMemberType;
use blazesym::symbolize::Resolve;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Error as BlazeErr;
use blazesym::Pid;

use clap::ArgAction;
use clap::Parser;

use debuginfod::BuildId;
use debuginfod::CachingClient;
use debuginfod::Client;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;


const ADDR_WIDTH: usize = 16;


fn parse_addr(s: &str) -> Result<Addr, String> {
    Addr::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|err| err.to_string())
}


/// A command line tool for symbolizing addresses in a process using
/// `debuginfod` fetched information.
#[derive(Debug, Parser)]
pub struct Args {
    /// The PID of the process to symbolize addresses of.
    pub pid: u32,
    /// The addresses to symbolize.
    #[clap(value_parser = parse_addr)]
    pub addrs: Vec<Addr>,
    /// Increase verbosity (can be supplied multiple times).
    #[clap(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    pub verbosity: u8,
}


fn print_frame(name: &str, addr_info: Option<(Addr, Addr, usize)>, code_info: &Option<CodeInfo>) {
    let code_info = code_info.as_ref().map(|code_info| {
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
            "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or(""),
            width = ADDR_WIDTH
        )
    } else {
        // Otherwise we are dealing with an inlined call.
        println!(
            "{:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
        )
    }
}

fn print_symbols<'s, S>(syms: S)
where
    S: IntoIterator<Item = (Addr, Symbolized<'s>)>,
{
    for (input_addr, sym) in syms {
        match sym {
            Symbolized::Sym(Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                print_frame(&name, Some((input_addr, addr, offset)), &code_info);
                for frame in inlined.iter() {
                    print_frame(&frame.name, None, &frame.code_info);
                }
            }
            Symbolized::Unknown(..) => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }
}


fn dispatch_process(
    info: ProcessMemberInfo<'_>,
    client: &CachingClient,
) -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
    let ProcessMemberInfo {
        member_entry: entry,
        ..
    } = info;

    match entry {
        ProcessMemberType::Path(path) => {
            let build_id = if let Some(build_id) = read_elf_build_id(&path.maps_file)? {
                build_id
            } else {
                // The binary does not contain a build ID, so we cannot
                // retrieve symbol data. Just let the default resolver do
                // its thing.
                return Ok(None)
            };

            let path = if let Some(path) = client
                .fetch_debug_info(&BuildId::raw(build_id))
                .map_err(Box::from)?
            {
                path
            } else {
                // If we were unable to find debug information for the provided
                // build ID we let the default resolver see what it can do.
                return Ok(None)
            };

            let resolver = ElfResolver::open(&path)
                .with_context(|| format!("failed to create ELF resolver for `{}`", path.display()))
                .map_err(Box::from)?;
            Ok(Some(Box::new(resolver)))
        }
        ProcessMemberType::Component(..) => Ok(None),
        _ => Ok(None),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let level = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_timer(SystemTime)
        .finish();

    set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;

    let client = Client::from_env()
        .context("failed to create debuginfod client")?
        .context("failed to find valid URLs in DEBUGINFOD_URLS environment variable")?;
    let client = CachingClient::from_env(client)?;

    let src = symbolize::Source::Process(symbolize::Process::new(Pid::from(args.pid)));
    let symbolizer = Symbolizer::builder()
        .set_process_dispatcher(move |info| dispatch_process(info, &client))
        .build();
    let syms = symbolizer
        .symbolize(&src, Input::AbsAddr(&args.addrs))
        .map_err(Error::from)
        .context("failed to symbolize addresses")?;
    print_symbols(args.addrs.iter().copied().zip(syms));
    Ok(())
}

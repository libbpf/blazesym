use anyhow::Context as _;
use anyhow::Result;

use blazesym::Addr;
use blazesym::Pid;

use clap::ArgAction;
use clap::Args as Arguments;
use clap::Parser;
use clap::Subcommand;


/// Parse a PID from a string.
fn parse_pid(s: &str) -> Result<Pid> {
    let pid = if let Some(s) = s.strip_prefix("0x") {
        u32::from_str_radix(s, 16)
    } else {
        s.parse::<u32>()
    }
    .with_context(|| format!("failed to parse PID: {s}"))?;

    Ok(Pid::from(pid))
}

/// Parse an addr from a string.
fn parse_addr(s: &str) -> Result<Addr> {
    Addr::from_str_radix(s.trim_start_matches("0x"), 16)
        .with_context(|| format!("failed to parse address: {s}"))
}


/// A command line interface for blazesym.
#[derive(Debug, Parser)]
#[clap(version = env!("VERSION"))]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
    /// Increase verbosity (can be supplied multiple times).
    #[clap(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    pub verbosity: u8,
}


#[derive(Debug, Subcommand)]
pub enum Command {
    /// Symbolize one or more addresses.
    #[command(subcommand)]
    Symbolize(Symbolize),
}


/// An type representing the `backup` command.
#[derive(Debug, Subcommand)]
pub enum Symbolize {
    Process(Process),
}

#[derive(Debug, Arguments)]
pub struct Process {
    /// The PID of the process the provided addresses belong to.
    #[arg(value_parser = parse_pid)]
    pub pid: Pid,
    /// The addresses to symbolize.
    #[arg(value_parser = parse_addr)]
    pub addrs: Vec<Addr>,
}

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::Result;

use blazesym::Addr;
use blazesym::Pid;

use clap::ArgAction;
use clap::Args as Arguments;
use clap::Parser;
use clap::Subcommand;
use clap::ValueHint;


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

/// Parse an address from a string.
fn parse_addr(s: &str) -> Result<Addr> {
    // In our world addresses are always represented in hex, with or without 0x
    // prefix.
    Addr::from_str_radix(s.trim_start_matches("0x"), 16)
        .with_context(|| format!("failed to parse address: {s}"))
}


/// A command line interface for blazesym.
#[derive(Debug, Parser)]
#[command(version = env!("VERSION"))]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
    /// Increase verbosity (can be supplied multiple times).
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    pub verbosity: u8,
}


#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect a symbol source.
    #[command(subcommand)]
    Inspect(inspect::Inspect),
    /// Normalize one or more addresses.
    #[command(subcommand)]
    Normalize(normalize::Normalize),
    /// Symbolize one or more addresses.
    #[command(subcommand)]
    Symbolize(symbolize::Symbolize),
}


pub mod inspect {
    use super::*;


    /// A type representing the `inspect` command.
    #[derive(Debug, Subcommand)]
    pub enum Inspect {
        #[command(subcommand)]
        Dump(Dump),
        #[command(subcommand)]
        Lookup(Lookup),
        #[command(subcommand, name = "buildid")]
        BuildId(BuildId),
    }

    /// A type representing the `inspect lookup` sub-command.
    #[derive(Debug, Subcommand)]
    pub enum Lookup {
        /// Lookup symbols in a Breakpad file by name.
        Breakpad(BreakpadLookup),
        /// Lookup symbols in a ELF file by name.
        Elf(ElfLookup),
    }

    /// A type representing the `inspect dump` sub-command.
    #[derive(Debug, Subcommand)]
    pub enum Dump {
        /// Dump all symbols in a Breakpad file.
        Breakpad(BreakpadDump),
        /// Dump all symbols in an ELF file.
        Elf(ElfDump),
    }

    /// A type representing the `inspect buildid` sub-command.
    #[derive(Debug, Subcommand)]
    pub enum BuildId {
        /// Read the build ID of an ELF file.
        Elf { path: PathBuf },
    }

    #[derive(Debug, Arguments)]
    pub struct BreakpadLookup {
        /// The path to the Breakpad (*.sym) file.
        #[arg(short, long)]
        pub path: PathBuf,
        /// A list of names of symbols.
        pub names: Vec<String>,
    }

    #[derive(Debug, Arguments)]
    pub struct BreakpadDump {
        /// The path to the Breakpad (*.sym) file.
        #[arg(short, long)]
        pub path: PathBuf,
    }

    #[derive(Debug, Arguments)]
    pub struct ElfLookup {
        /// The path to the ELF file.
        #[arg(short, long)]
        pub path: PathBuf,
        /// A list of names of symbols.
        pub names: Vec<String>,
    }

    #[derive(Debug, Arguments)]
    pub struct ElfDump {
        /// The path to the ELF file.
        #[arg(short, long)]
        pub path: PathBuf,
        /// Dump ELF symbols instead of DWARF ones.
        #[arg(long)]
        pub no_debug_syms: bool,
    }
}


pub mod normalize {
    use super::*;


    /// A type representing the `normalize` command.
    #[derive(Debug, Subcommand)]
    pub enum Normalize {
        /// Normalize user space addresses.
        User(User),
    }

    #[derive(Debug, Arguments)]
    pub struct User {
        /// The PID of the process the provided addresses belong to.
        #[arg(short, long, value_parser = parse_pid)]
        pub pid: Pid,
        /// The addresses to normalize.
        #[arg(value_parser = parse_addr)]
        pub addrs: Vec<Addr>,
        /// Disable the reading of build IDs of the corresponding binaries.
        #[arg(long)]
        pub no_build_ids: bool,
        /// Report `/proc/<pid>/map_files/` entry paths instead of
        /// symbolic paths mentioned in `/proc/<pid>/maps`.
        #[arg(long)]
        pub map_files: bool,
        /// Enable the usage of the `PROCMAP_QUERY` ioctl instead of
        /// parsing `/proc/<pid>/maps` for getting available VMA ranges.
        #[arg(long)]
        pub procmap_query: bool,
    }
}


pub mod symbolize {
    use super::*;


    /// A type representing the `symbolize` command.
    #[derive(Debug, Subcommand)]
    pub enum Symbolize {
        Breakpad(Breakpad),
        Elf(Elf),
        Gsym(Gsym),
        Process(Process),
        Kernel(Kernel),
    }

    #[derive(Debug, Arguments)]
    pub struct Breakpad {
        /// The path to the Breakpad (*.sym) file.
        #[arg(short, long)]
        pub path: PathBuf,
        /// The addresses to symbolize.
        ///
        /// Addresses are assumed to be file offsets as they would be used on
        /// the original (ELF/DWARF/...) source file.
        #[arg(value_parser = parse_addr)]
        pub addrs: Vec<Addr>,
    }

    #[derive(Debug, Arguments)]
    #[group(multiple = false)]
    pub struct DebugArgs {
        /// Comma-separated list of debug directories to search when
        /// resolving debug links.
        #[arg(long, value_parser, value_delimiter = ',')]
        pub debug_dirs: Option<Vec<PathBuf>>,
        /// Disable the use of debug symbols.
        #[arg(long)]
        pub no_debug_syms: bool,
    }

    #[derive(Debug, Arguments)]
    pub struct Elf {
        /// The path to the ELF file.
        #[arg(short, long)]
        pub path: PathBuf,
        #[command(flatten)]
        pub debug_args: DebugArgs,
        /// The addresses to symbolize.
        ///
        /// Addresses are assumed to already be normalized to the file
        /// itself (i.e., with relocation and address randomization effects
        /// removed).
        #[arg(value_parser = parse_addr)]
        pub addrs: Vec<Addr>,
    }

    #[derive(Debug, Arguments)]
    pub struct Gsym {
        /// The path to the Gsym file.
        #[arg(short, long)]
        pub path: PathBuf,
        /// The addresses to symbolize.
        ///
        /// Addresses are assumed to already be normalized to the file
        /// itself (i.e., with relocation and address randomization effects
        /// removed).
        #[arg(value_parser = parse_addr)]
        pub addrs: Vec<Addr>,
    }

    #[derive(Debug, Arguments)]
    pub struct Process {
        /// The PID of the process the provided addresses belong to.
        #[arg(short, long, value_parser = parse_pid)]
        pub pid: Pid,
        /// The addresses to symbolize.
        #[arg(value_parser = parse_addr)]
        pub addrs: Vec<Addr>,
        /// Disable the use of `/proc/<pid>/map_files/` entries and use
        /// symbolic paths instead.
        #[arg(long)]
        pub no_map_files: bool,
    }

    #[derive(Debug, Arguments)]
    pub struct Kernel {
        /// The kallsyms file to use. Defaults to the system one. To
        /// disable kallsyms usage provide an empty argument.
        // We use `OsString`, because it natively supports ""
        // assignment, whereas `PathBuf` does not.
        #[arg(long, value_hint = ValueHint::FilePath)]
        pub kallsyms: Option<OsString>,
        /// The vmlinux file to use. If not provided, default system
        /// locations will be searched for suitable candidates. To
        /// disable usage provide an empty argument.
        #[arg(long, value_hint = ValueHint::FilePath)]
        pub vmlinux: Option<OsString>,
        /// The addresses to symbolize.
        #[arg(value_parser = parse_addr)]
        pub addrs: Vec<Addr>,
    }
}

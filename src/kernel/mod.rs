#[cfg(feature = "bpf")]
mod bpf;
mod cache;
mod depmod;
mod kaslr;
mod ksym;
mod modmap;
mod resolver;

/// The path to the `/proc/kallsyms` file.
const KALLSYMS: &str = "/proc/kallsyms";
/// The path to the `/proc/modules` file.
const MODULES: &str = "/proc/modules";

use self::depmod::DepmodIndex;
use self::modmap::ModMap;

pub(crate) use cache::KernelCache;
pub(crate) use resolver::KernelResolver;

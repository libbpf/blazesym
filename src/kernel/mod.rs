#[cfg(feature = "bpf")]
mod bpf;
mod kaslr;
mod ksym;
mod resolver;

/// The path to the `/proc/kallsyms` file.
pub(crate) const KALLSYMS: &str = "/proc/kallsyms";

// TODO: KsymResolver should ideally be an implementation detail.
pub(crate) use kaslr::find_kalsr_offset;
pub(crate) use ksym::KsymResolver;
pub(crate) use resolver::KernelResolver;

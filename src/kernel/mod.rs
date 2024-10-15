mod ksym;
mod resolver;

// TODO: KsymResolver should ideally be an implementation detail.
pub(crate) use ksym::KSymResolver;
pub(crate) use ksym::KALLSYMS;
pub(crate) use resolver::KernelResolver;

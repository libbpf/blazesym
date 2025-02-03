mod parser;
#[cfg_attr(not(feature = "dwarf"), allow(unused_variables))]
mod resolver;
#[allow(dead_code, non_camel_case_types)]
pub(crate) mod types;

// Please adjust the documentation when adjusting directories.
// We use `str` here because `Path` is basically inconstructible in
// const contexts :-|
// TODO: Conceptually belongs into `dwarf` module, but with current separation
//       of concerns that is not a workable location.
pub(crate) static DEFAULT_DEBUG_DIRS: &[&str] = &["/usr/lib/debug", "/lib/debug/"];

pub(crate) use parser::BackendImpl;
pub(crate) use parser::ElfParser;
pub(crate) use resolver::ElfResolverData;

pub use resolver::ElfResolver;

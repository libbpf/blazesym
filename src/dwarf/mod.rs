#[allow(non_upper_case_globals, unused)]
mod constants;
#[allow(non_upper_case_globals)]
mod debug_info;
mod parser;
mod resolver;

pub use self::resolver::DwarfResolver;

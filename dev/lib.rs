//! Supporting dev-only functionality for `blazesym`.

#[cfg(linux)]
mod bpf;
mod criterion;

#[cfg(linux)]
pub use bpf::*;

pub use crate::criterion::config as criterion_config;

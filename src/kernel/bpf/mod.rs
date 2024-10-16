#[cfg(not(target_os = "linux"))]
compile_error!("BPF support is only present on Linux, please disable `bpf` feature");

mod btf;
mod prog;
mod sys;

use btf::Btf;

pub(super) use prog::BpfProg;
#[cfg(test)]
pub(super) use prog::BpfTag;

[![pipeline](https://github.com/libbpf/blazesym/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/libbpf/blazesym/actions/workflows/test.yml)
[![crates.io](https://img.shields.io/crates/v/blazesym-c.svg)](https://crates.io/crates/blazesym-c)
[![rustc](https://img.shields.io/badge/rustc-1.88+-blue.svg)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)

blazesym-c
==========

- [Changelog](CHANGELOG.md)

**blazesym-c** provides C language bindings for the [**blazesym**][blazesym]
library.

Please note that this library adheres to Cargo's [semantic versioning
rules][cargo-semver]. While it is likely that the ABI is sufficiently
flexible to cover incompatible versions, you do so at your own risk.

## Build & Use
**blazesym-c** requires a standard Rust toolchain and can be built using
the Cargo project manager (e.g., `cargo build`).

The build will produce `libblazesym_c.a` as well as `libblazesym_c.so` in
the respective target folder (e.g., `<project-root>/target/debug/`).

In your C programs include [`blazesym.h`](include/blazesym.h) (provided as part
of the crate) from your source code and then link against the static or
shared library, respectively. When linking statically, you may also need
to link:
```text
-lrt -ldl -lpthread -lm
```

An example of usage of the C API is in available in **libbpf-bootstrap**:
<https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/profile.c>

This example periodically samples the running process of every processor
in a system and prints their stack traces.

A detailed [documentation of the C API](https://docs.rs/blazesym-c/latest/)
is available as part of the Rust documentation or can be generated locally from
the current repository snapshot using `cargo doc`.

[blazesym]: https://crates.io/crates/blazesym
[cargo-semver]: https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility

[![pipeline](https://github.com/libbpf/blazesym/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/libbpf/blazesym/actions/workflows/test.yml)
[![coverage](https://codecov.io/gh/libbpf/blazesym/branch/main/graph/badge.svg)](https://codecov.io/gh/libbpf/blazesym)
[![crates.io](https://img.shields.io/crates/v/blazesym.svg)](https://crates.io/crates/blazesym)
[![Docs](https://docs.rs/blazesym/badge.svg)](https://docs.rs/blazesym)
[![rustc](https://img.shields.io/badge/rustc-1.63+-blue.svg)](https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html)

# blazesym

- [Changelog](CHANGELOG.md)

**blazesym** is a library that can be used to symbolize addresses. Address
symbolization is a common problem in tracing contexts, for example, where users
want to reason about functions by name, but low level components report only the
"raw" addresses (e.g., in the form of stacktraces).

In addition to symbolization, **blazesym** also provides APIs for the reverse
operation: looking up addresses from symbol names. That can be useful, for
example, for configuring breakpoints or tracepoints.

The library aims to provide a "batteries-included" experience. That is to say,
it tries to do the expected thing by default. When offering such convenience
comes at the cost of performance, we aim to provide advanced APIs that allow for
runtime configuration of the corresponding features.

The library is written in Rust and provides a first class C API. This crate
adheres to Cargo's [semantic versioning rules][cargo-semver]. At a minimum, it
builds with the most recent Rust stable release minus five minor versions ("N -
5"). E.g., assuming the most recent Rust stable is `1.68`, the crate is
guaranteed to build with `1.63` and higher.


## Status
**blazesym** is being actively worked on. Feel free to contribute with
discussions, feature suggestions, or code contributions!

Here is rough roadmap of currently planned features (in no particular order):

- [ ] Fully support handling of kernel addresses
  - currently normalization APIs, for example, only support user space addresses
- [ ] Optimize normalization logic with more aggressive caching
- [ ] Switch to using [`gimli`](https://crates.io/crates/gimli) for DWARF parsing
  - doing so will allow us to:
    - [ ] Support more versions of the DWARF standard (https://github.com/libbpf/blazesym/issues/42 & https://github.com/libbpf/blazesym/issues/57)
    - [ ] Support split debug information (https://github.com/libbpf/blazesym/issues/60)
- [ ] Support symbolization of addresses in APKs (relevant for Android)
- [ ] Support ELF32 binaries (https://github.com/libbpf/blazesym/issues/53)
- [ ] Support demangling of Rust & C++ symbol names (https://github.com/libbpf/blazesym/issues/50)
- [ ] Support remote symbolization (https://github.com/libbpf/blazesym/issues/61)
  - [x] Add APIs for address normalization (https://github.com/libbpf/blazesym/pull/114, https://github.com/libbpf/blazesym/pull/128, ...)
- [ ] Support advanced symbolization use cases involving [`debuginfod`](https://sourceware.org/elfutils/Debuginfod.html)


## Build & Use
**blazesym** requires a standard Rust toolchain and can be built using the Cargo
project manager (e.g., `cargo build`).

### Rust
Consumption from a Rust project should happen via `Cargo.toml`:
```toml
[dependencies]
blazesym = "0.2.0-alpha.2"
```

For a quick set of examples please refer to the [`examples/` folder](examples/).
Please refer to the [documentation](https://docs.rs/blazesym) for a
comprehensive explanation of individual types and functions.


### C
For C interoperability, the aforementioned build will produce `libblazesym.a` as
well as `libblazesym.so` in the respective target folder (e.g.,
`<project-root>/target/debug/`).

In your C programs include [`blazesym.h`](include/blazesym.h) (provided as part
of the library) from your source code and then link against the static or shared
library, respectively. When linking statically, you may also need to link:
```text
-lrt -ldl -lpthread -lm
```

An example of usage of the C API is in available in **libbpf-bootstrap**:
<https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/profile.c>

This example periodically samples the running process of every processor
in a system and prints their stack traces.

A detailed [documentation of the C API](https://docs.rs/blazesym/latest/blazesym/c_api)
is available as part of the Rust documentation or can be generated locally from
the current repository snapshot using `cargo doc` (grouped under the `c_api`
module).


[cargo-semver]: https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility

[![pipeline](https://github.com/libbpf/blazesym/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/libbpf/blazesym/actions/workflows/test.yml)
[![coverage](https://codecov.io/gh/libbpf/blazesym/branch/main/graph/badge.svg)](https://codecov.io/gh/libbpf/blazesym)
[![crates.io](https://img.shields.io/crates/v/blazesym.svg)](https://crates.io/crates/blazesym)
[![Docs](https://docs.rs/blazesym/badge.svg)](https://docs.rs/blazesym)
[![rustc](https://img.shields.io/badge/rustc-1.65+-blue.svg)](https://blog.rust-lang.org/2022/11/03/Rust-1.65.0.html)

# blazesym

- [Changelog](CHANGELOG.md)
- [Developer Resources](README-devel.md)

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

**blazesym** supports a variety of formats, such as DWARF, ELF, and Gsym (see
below for an up-to-date list).

The library is written in Rust and provides a first class C API. This crate
adheres to Cargo's [semantic versioning rules][cargo-semver]. At a minimum, it
builds with the most recent Rust stable release minus five minor versions ("N -
5"). E.g., assuming the most recent Rust stable is `1.68`, the crate is
guaranteed to build with `1.63` and higher.


## Status
**blazesym** is being actively worked on. Feel free to contribute with
discussions, feature suggestions, or code contributions!

As alluded to above, the library provides support for a variety of formats. For
symbolization specifically, the following table lays out what features each
format supports and whether **blazesym** can currently use this feature:

| Format        | Feature                          | Supported by format?     | Supported by blazesym?   |
| ------------- | -------------------------------- | ------------------------ | ------------------------ |
| Breakpad      | symbol size                      | :heavy_check_mark:       | :heavy_check_mark:       |
|               | source code location information | :heavy_check_mark:       | :heavy_check_mark:       |
|               | inlined function information     | :heavy_check_mark:       | :heavy_check_mark:       |
| ELF           | symbol size                      | :heavy_check_mark:       | :heavy_check_mark:       |
|               | source code location information | :heavy_multiplication_x: | :heavy_multiplication_x: |
|               | inlined function information     | :heavy_multiplication_x: | :heavy_multiplication_x: |
| DWARF         | symbol size                      | :heavy_check_mark:       | :heavy_check_mark:       |
|               | source code location information | :heavy_check_mark:       | :heavy_check_mark:       |
|               | inlined function information     | :heavy_check_mark:       | :heavy_check_mark:       |
| Gsym          | symbol size                      | :heavy_check_mark:       | :heavy_check_mark:       |
|               | source code location information | :heavy_check_mark:       | :heavy_check_mark:       |
|               | inlined function information     | :heavy_check_mark:       | :heavy_check_mark:       |
| Ksym          | symbol size                      | :heavy_multiplication_x: | :heavy_multiplication_x: |
|               | source code location information | :heavy_multiplication_x: | :heavy_multiplication_x: |
|               | inlined function information     | :heavy_multiplication_x: | :heavy_multiplication_x: |


Here is rough roadmap of currently planned features (in no particular order):

- [ ] Fully support handling of kernel addresses
  - currently normalization APIs, for example, only support user space addresses
- [x] Switch to using [`gimli`](https://crates.io/crates/gimli) for DWARF parsing
  - doing so will allow us to:
    - [x] Support more versions of the DWARF standard (https://github.com/libbpf/blazesym/issues/42 & https://github.com/libbpf/blazesym/issues/57)
    - [ ] Support split debug information (https://github.com/libbpf/blazesym/issues/60)
    - [x] Support inlined function lookup for DWARF (https://github.com/libbpf/blazesym/issues/192)
- [x] Support symbolization of addresses in APKs (relevant for Android) (https://github.com/libbpf/blazesym/pull/222 & https://github.com/libbpf/blazesym/pull/227)
- [ ] Support ELF32 binaries (https://github.com/libbpf/blazesym/issues/53)
- [x] Support demangling of Rust & C++ symbol names (https://github.com/libbpf/blazesym/issues/50)
- [x] Support remote symbolization (https://github.com/libbpf/blazesym/issues/61)
  - [x] Add APIs for address normalization (https://github.com/libbpf/blazesym/pull/114, https://github.com/libbpf/blazesym/pull/128, ...)
- [ ] Support advanced symbolization use cases involving [`debuginfod`](https://sourceware.org/elfutils/Debuginfod.html) (https://github.com/libbpf/blazesym/issues/203)


## Build & Use
**blazesym** requires a standard Rust toolchain and can be built using the Cargo
project manager (e.g., `cargo build`).

### Rust
Consumption from a Rust project should happen via `Cargo.toml`:
```toml
[dependencies]
blazesym = "=0.2.0-alpha.11"
```

For a quick set of examples please refer to the [`examples/` folder](examples/).
Please refer to the [documentation](https://docs.rs/blazesym) for a
comprehensive explanation of individual types and functions.


### C
The companion crate [`blazesym-c`](capi/) provides the means for interfacing
with the library from C. Please refer to its [`README`](capi/README.md) for
usage details.


### Command-line
The library also comes with a [command line interface](cli/) for quick
experimentation and debugging. You can run it directly from the
repository, e.g.:
```sh
cargo run -p blazecli -- symbolize elf --path /lib64/libc.so.6 00000000000caee1
```

Please refer to its [`README`](cli/README.md) as well as the help text
for additional information and usage instructions.


[cargo-semver]: https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility

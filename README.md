[![pipeline](https://github.com/libbpf/blazesym/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/libbpf/blazesym/actions/workflows/test.yml)
[![coverage](https://codecov.io/gh/libbpf/blazesym/branch/main/graph/badge.svg)](https://codecov.io/gh/libbpf/blazesym)
[![crates.io](https://img.shields.io/crates/v/blazesym.svg)](https://crates.io/crates/blazesym)
[![Docs](https://docs.rs/blazesym/badge.svg)](https://docs.rs/blazesym)
[![rustc](https://img.shields.io/badge/rustc-1.69+-blue.svg)](https://blog.rust-lang.org/2023/04/20/Rust-1.69.0.html)

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

**blazesym** supports a variety of formats, such as DWARF, ELF, Breakpad, and
Gsym (see below for an up-to-date list).

The library is written in Rust and provides a first class C API. This crate
adheres to Cargo's [semantic versioning rules][cargo-semver]. At a minimum, it
builds with the most recent Rust stable release minus five minor versions ("N -
5"). E.g., assuming the most recent Rust stable is `1.68`, the crate is
guaranteed to build with `1.63` and higher.


## Status
**blazesym** is at the core of Meta's internal continuous profiling solution,
where it handles billions of symbolization requests per day.

The library is being actively worked on, with a major goal being stabilization
of the API surface. Feel free to contribute with discussions, feature
suggestions, or code contributions!

As alluded to above, the library provides support for a variety of formats. For
symbolization specifically, the following table lays out what features each
format supports and whether **blazesym** can currently use this feature:

| Format        | Feature                          | Supported by format? | Supported by blazesym? |
| ------------- | -------------------------------- | -------------------- | ---------------------- |
| Breakpad      | symbol size                      | ✔️                    | ✔️                      |
|               | source code location information | ✔️                    | ✔️                      |
|               | inlined function information     | ✔️                    | ✔️                      |
| ELF           | symbol size                      | ✔️                    | ✔️                      |
|               | source code location information | ✖️                    | ✖️                      |
|               | inlined function information     | ✖️                    | ✖️                      |
| DWARF         | symbol size                      | ✔️                    | ✔️                      |
|               | source code location information | ✔️                    | ✔️                      |
|               | inlined function information     | ✔️                    | ✔️                      |
| Gsym          | symbol size                      | ✔️                    | ✔️                      |
|               | source code location information | ✔️                    | ✔️                      |
|               | inlined function information     | ✔️                    | ✔️                      |
| Ksym          | symbol size                      | ✖️                    | ✖️                      |
|               | source code location information | ✖️                    | ✖️                      |
|               | inlined function information     | ✖️                    | ✖️                      |
| BPF program   | symbol size                      | ✖️ (?)                | ✖️                      |
|               | source code location information | ✔️                    | ✔️                      |
|               | inlined function information     | ✖️                    | ✖️                      |


### OS Support
The library's primary target operating system is Linux (it should work on all
semi-recent kernel versions and distributions).

MacOS and Windows are supported for file based symbolization (i.e., using one of
the `Breakpad`, `Elf`, or `Gsym` symbolization sources). Standalone address
normalization as well as process or kernel symbolization are not supported.


## Build & Use
**blazesym** requires a standard Rust toolchain and can be built using the Cargo
project manager (e.g., `cargo build`).

### Rust
Consumption from a Rust project should happen via `Cargo.toml`:
```toml
[dependencies]
blazesym = "=0.2.0-rc.2"
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

Statically linked binaries for various target triples are available on-demand
[here][blazecli-bins].


[blazecli-bins]: https://github.com/libbpf/blazesym/actions/workflows/build-cli.yml
[cargo-semver]: https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility

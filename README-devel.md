# Developer Notes

## C API
Our [C API header](capi/include/blazesym.h) is version controlled and
programmatically generated from Rust definitions. If you are introducing
a new public C API function, you will have to re-generate it to make the
new function available.

The following command can be used for doing that:
```sh
$ cargo check --package blazesym-c --features=generate-c-header
```


## Testing
All our testing is `cargo` based and a simple
```sh
$ cargo test --workspace
```
runs the vast majority of tests. Tests require `sudo` to be set up properly, as
some of the functionality we rely on is privileged. Test artifacts are
transparently created as long as the `generate-unit-test-files` feature is
active, which is enabled by default for testing.

### Running Miri
[Miri][miri] is used for testing the crate for any undefined behavior.
The interpreter is restricted to functionality that does not cross FFI
boundaries and won't perform I/O. To run all eligible tests, use:
```sh
# Miri usage conflicts with custom test runners, so don't over write it.
$ rm .cargo/config.toml
$ MIRIFLAGS='-Zmiri-disable-stacked-borrows' cargo miri test --workspace -- ":miri:"
```

### Documentation
To generate the documentation as it would appear on `docs.rs` once a
new release is published, run:
```sh
RUSTDOCFLAGS='--cfg docsrs' cargo doc --open --features="apk,backtrace,breakpad,demangle,dwarf,gsym"
```


## Benchmarking
We use a mixture of [Criterion][criterion] end-to-end benchmarks and [`libtest`
based][libtest] unit-test style ones.

To run the benchmark suite, use:
```sh
# Perform one-time setup of required data.
$ cargo check --features=generate-large-test-files
$ cargo bench --features=nightly
```

Some benchmarks require the `PROCMAP_QUERY` ioctl kernel functionality,
which is not yet widely available. As such, they are disabled by
default. To enable them set the `RUSTFLAGS` environment variable to
`--cfg has_procmap_query_ioctl`.

For all Criterion powered benchmarks, a run will automatically establish a new
base line. You can check out a different change, re-run the above command, and
it will print the performance difference.


### CPU Profiling
To get a CPU profile in the form of a flamegraph, you can use
[`cargo-flamegraph`][flamegraph] (can be installed via `cargo install
flamegraph`). The following command will create a profile for the
`bench_function_parsing_blazesym` benchmark, for example:
```sh
$ cargo flamegraph --package=blazesym --unit-bench --root --features=nightly -- bench_function_parsing_blazesym
```

For Criterion based benchmarks, use:
```sh
$ cargo flamegraph --bench=main --root --features=nightly -- symbolize_gsym_multi_no_setup --bench
```


### Allocation Profiling
The crate comes with custom infrastructure for gathering memory
allocation statistics and to print backtraces for allocations, in the
[`allocs`][blazesym-allocs] test. This is not meant as a general purpose
memory profiler, but it is built-in functionality that does not require
additional tools to be installed.

It is meant to be used for performance sensitive paths for which we want
to understand allocation behavior and potentially make assertions about
the number of allocations performed (if deterministic).

To use it, run:
```sh
$ cargo test --test=allocs -- normalize_process --nocapture
```
where `normalize_process` is the name of the test you want to run. You
can conceivably run all tests, but given the multi-threaded nature of
the test runner, it is generally recommended to just focus on a single
one. This command will print allocation statistics once the test
concluded.

To additionally print backtraces, set the `RUST_LIB_BACKTRACE` (or
`RUST_BACKTRACE`) variable:

```sh
$ RUST_LIB_BACKTRACE=1 cargo test --test=allocs -- normalize_process --nocapture
# Loads of backtraces will be reported.
```


[blazesym-allocs]: https://github.com/libbpf/blazesym/blob/main/tests/allocs.rs
[criterion]: https://crates.io/crates/criterion
[flamegraph]: https://crates.io/crates/flamegraph
[libtest]: https://doc.rust-lang.org/1.4.0/book/benchmark-tests.html
[miri]: https://github.com/rust-lang/miri

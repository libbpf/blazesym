# Developer Notes

## Testing
All our testing is `cargo` based and a simple
```sh
$ cargo test
```
runs the vast majority of tests. Tests require `sudo` to be set up properly, as
some of the functionality we rely on is privileged. Test artifacts are
transparently created as long as the `generate-unit-test-files` feature is
active, which is enabled by default for testing.


## Benchmarking
We use a mixture of [Criterion][criterion] end-to-end benchmarks and [`libtest`
based][libtest] unit-test style ones.

To run the full benchmark suite, use:
```sh
# Perform one-time setup of required data.
$ cargo check --features=generate-large-test-files
$ cargo bench --features=nightly
```

For all Criterion powered benchmarks, a run will automatically establish a new
base line. You can check out a different change, re-run the above command, and
it will print the performance difference.


### Profiling
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

[criterion]: https://crates.io/crates/criterion
[flamegraph]: https://crates.io/crates/flamegraph
[libtest]: https://doc.rust-lang.org/1.4.0/book/benchmark-tests.html

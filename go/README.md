# blazsym-go

Go wrapper for C bindings of blazesym.

## Building

First of all, you need to have [blazesym-c](https://docs.rs/blazesym-c/) available on your system.
If it is installed in the expected places, everything should build out of the box.

If you don't have installed, you can build it yourself from [capi](../capi) dir in the repo:

```
cargo build --release
```

You can then pass flags to tell Go where to find things:

```
CGO_CFLAGS="-I/path/to/blazesym/capi/include" CGO_LDFLAGS="-L/path/to/blazesym/target/release"
```

At runtime you need to set `LD_LIBRARY_PATH=/path/to/blazesym/target/release`.

### Static linking

You might want to link against blazesym statically by adding the following to `CGO_LDFLAGS`:

```
-Wl,-Bstatic -lblazesym_c -Wl,-Bdynamic
```

This way `blazesym_c.so` doesn't need to be installed on the system where the binary will run.

Fully static builds are possible if you pass the following to `go build` or `go install`:

```
-ldflags='-extldflags "-static"'
```

### Example usage

See [example_source_elf_test.go](example_source_elf_test.go) for a basic example.

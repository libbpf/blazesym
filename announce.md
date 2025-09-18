# 🚀 Blazesym v0.2 Released!

We're thrilled to announce that after more than a dozen development releases, [**blazesym**](https://github.com/libbpf/blazesym) has reached a stable API with version [0.2.0](https://crates.io/crates/blazesym/0.2.0).

**blazesym** is a library for address symbolization -- the process of turning addresses ("pointers" if you will) into symbolic names that are human-readable. While other libraries exist in this space, **blazesym** stands out with:

1) Off-device symbolization
2) Multi-format support
3) Kernel symbolization
4) Symbol inspection
5) First-class C API

We will briefly go over these in a bit more detail below and will provide references for going deeper into the functionality.

If you are interested in seeing the library in action or trying it out right away, head over to the various [examples](https://github.com/libbpf/blazesym/tree/main/examples).


### Off-device Symbolization

Traditionally and in most environments, symbolization happens where the addresses are captured: if you capture a stack trace, you likely want symbolic names immediately. That is why in many cases you may not even be aware that addresses are just an intermediate step on the way to a human readable stack trace.

However, the act of turning addresses into symbol names is often costly (in terms of processing power required) and involves additional data to be available (ELF symbols which may otherwise be stripped, debug information which typically is not a requirement for running the program itself, ...). In embedded development and other contexts, it can thus be beneficial to do symbolization on a different machine.

**blazesym** formalizes this process and provides first-class API support in the form of the [normalization APIs](https://docs.rs/blazesym/0.2.*/blazesym/normalize/), which help "normalize" addresses and annotate them with metadata necessary to later perform symbolization elsewhere.


### Multi-format Support

On Linux the DWARF format is prevalent for all things debugging and it is used for symbolization as well. However, other formats with different strengths (and weaknesses) exist as well:
- [Gsym](https://reviews.llvm.org/D53379) is specifically designed around symbolization performance; as such it is orders of magnitude faster to handle than DWARF, while being smaller in size (we run benchmarks with files in various formats on each [`Test` CI run](https://github.com/libbpf/blazesym/actions/workflows/test.yml), so check out their summary for specific numbers)
- [Breakpad](https://github.com/google/breakpad/blob/main/docs/symbol_files.md) is often used in the Android ecosystem; it is also mostly used in symbolization contexts but is human readable (i.e., not a binary format) by design

**blazesym** supports these behind pay-for-what-you-use compile-time features (if you don't enable them, they are completely compiled out) and abstracts away details behind a unified API. The library is also open to supporting additional formats in the future.


### Kernel Symbolization

Application and service developers typically focus on user space and tooling is oftentimes only able to support that. But the kernel is part of any "full-stack".

**blazesym** is able to symbolize kernel addresses as well as user space ones[^1] for a "batteries-included" experience.

[^1]: There exist some limitations surrounding kernel address normalization (not supported at the moment) as well as symbolization (does not use DWARF debug information for kernel modules) that we intend to resolve with upcoming releases.


### Inspection

If symbolization describes the act of mapping addresses to symbol names, "inspection" refers to the inverse operation: the lookup of metadata (address, size, type, etc.) given a symbol name.

**blazesym** supports such a lookup by virtue of the ["inspect" APIs](https://docs.rs/blazesym/0.2.*/blazesym/inspect/). This functionality is useful in many contexts, but a typical example includes the retrieval of the file offset of a symbol to which to attach a [Uprobe](https://lwn.net/Articles/499190/).


### C API

It is widely accepted that C is the lingua franca in the world of computers. **blazesym** comes with a first-class API for usage with the C language via the [**blazesym-c** library](https://github.com/libbpf/blazesym/tree/main/capi). In so doing it aims to bring strong memory safety guarantees offered by the core Rust library into the world of C & C++, while also paving the way for use in any other language that has a C foreign language interface, such as Python.

As an example, [`bpftrace`](https://github.com/bpftrace/bpftrace), a popular project in the BPF/tracing realm that is written in C++, can use **blazesym** for its symbolization tasks.

-----------------------------------------------------------------------

## 🎉 Get Started & Contribute

We are excited for developers to explore **blazesym** v0.2 and welcome feedback and contributions from the community.

We would also like to extend our thanks to the engineers from DataDog, who were early adopters of the library in their [profiling solution](https://github.com/DataDog/ddprof).

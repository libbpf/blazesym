# Blazesym v0.2

I am happy to announce that, at long last, after more than a dozen
development releases, **blazesym** is available with a stable API in
version [0.2.0](https://crates.io/crates/blazesym/0.2.0).

**blazesym** is a library for address symbolization, i.e., the process
of turning addresses ("pointers" if you will) into symbolic names that
humans can reason about. It is not alone in this space, but it has a few
features that make it stand out:

1) Support for off-device symbolization
2) Multi-format support
3) Kernel symbolization support
4) "Inspection" support
5) A first class C API

We will briefly go over these in a bit more detail below and will
provide references for going deeper into the functionality.


### Off-device Symbolization

Traditionally and in most environments, symbolization is happening where
the addresses are captured: if you capture a stack trace somewhere
chances are you are interested in the symbolic names then and there.
That is why in many cases you may not even be aware that addresses are
likely an intermediate step on the way to a human readable stack trace.

However, the act of turning addresses into symbol names is often costly
(in terms of processing power required) and involves additional data to
be available (ELF symbols which may otherwise be stripped, debug
information which typically is not a requirement for running the program
itself, ...). In embedded development and other contexts, it can thus be
beneficial to do symbolization on a different machine.

**blazesym** formalizes this process and provides first class API
support in the form of the [normalization
APIs](https://docs.rs/blazesym/0.2.*/blazesym/normalize/), which help
"normalize" addresses and annotate them with metadata necessary to later
perform symbolization elsewhere.


### Multi-format Support

On Linux the DWARF format is prevalent for all things debugging and it
is used for symbolization as well. However, other formats with different
strengths (and weaknesses) exist as well:
- [Gsym](https://reviews.llvm.org/D53379) is specifically design around
  symbolization performance; as such it is orders of magnitude faster to
  handle than DWARF, while being smaller in size
- [Breakpad](https://github.com/google/breakpad/blob/main/docs/symbol_files.md)
  is often used in the Android ecosystem; it is also mostly used in
  symbolization contexts but is human readable (i.e., not a binary
  format) by design

**blazesym** supports these behind pay-for-what-you-use compile-time
features and abstracts away details behind a unified API. The library is
also open to supporting additional formats in the future.


### Kernel Symbolization

Application and service developers typically concern themselves mostly
with user space and tooling is oftentimes only able to support that. But
the kernel is part of any "full-stack".

**blazesym** is able to symbolize kernel addresses as well as user space
ones[^1] for a batteries-included experience.

[^1]: There exist some limitation surrounding kernel address
    normalization as well as symbolization that we intend to resolve
    with upcoming releases.


### Inspection

If symbolization describes the act of mapping addresses to symbol names,
"inspection" refers to the inverse operation: the lookup of meta
data (address, size, type, etc.) given a symbol name.

**blazesym** supports such a lookup by virtue of the ["inspect"
APIs](APIs](https://docs.rs/blazesym/0.2.*/blazesym/inspect/). Such
functionality can come in handy in many contexts, but a typical example
includes the retrieval of the file offset of a symbol to which to attach
a [Uprobe](https://lwn.net/Articles/499190/).


### C API

It is widely accepted that C is the lingua franca in the world of
computers. **blazesym** comes with a first class API for usage with the
C language via the [**blazesym-c**
library](https://github.com/libbpf/blazesym/tree/main/capi). In so doing
it aims to being strong memory safety guarantees offered by the core
Rust library into the world of C & C++, while paving the way for usage
in any other language that has a C foreign language interface, such as
Python.

-----------------------------------------------------------------------

XXX

Special thanks to the engineers from DataDog, who were early adopters of
the library for their profiling solution.

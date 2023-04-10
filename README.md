# BlazeSym

BlazeSym is a library that symbolizes addresses where symbol names,
source file names, and line numbers can be acquired.  It can translate stack
traces to function names and their locations in the
source code.

 - <https://github.com/libbpf/blazesym>

## Build

To build BlazeSym, you must install a Rust environment.

Once successfully installed, you must obtain BlazeSym's source code.

 - `git clone https://github.com/libbpf/blazesym.git`

Next, you would need to go to the root directory of the BlazeSym source code
to build BlazeSym.

 - cargo build

You will see **libblazesym.a** in `target/debug/` or `target/release/`
directory. The corresponding **blazesym.h** header file is located
inside `include/`. Your C programs, if any, should include
**blazesym.h** and link to **libblazesym.a** to access functions and
various types of BlazeSym.

## Rust API

The following code makes use of BlazeSym to access symbol names, filenames of
sources, and line numbers of addresses involved in a process.

```rust,no_run
  use blazesym::cfg;
  use blazesym::Addr;
  use blazesym::BlazeSymbolizer;
  use blazesym::SymbolSrcCfg;
  use blazesym::SymbolizedResult;

  let process_id: u32 = std::process::id(); // <some process id>
  // load all symbols of loaded files of the given process.
  let sym_srcs = [
    SymbolSrcCfg::Process(cfg::Process { pid: Some(process_id) })
  ];
  let symbolizer = BlazeSymbolizer::new().unwrap();

  let stack: [Addr; 2] = [0xff023, 0x17ff93b];    // Addresses of instructions
  let symlist = symbolizer.symbolize(&sym_srcs,   // Pass this configuration every time
                                     &stack).unwrap();
  for i in 0..stack.len() {
    let address = stack[i];

    if symlist.len() <= i || symlist[i].len() == 0 {  // Unknown address
      println!("0x{:016x}", address);
      continue;
    }

    let sym_results = &symlist[i];
    if sym_results.len() > 1 {
      // One address may get several results (ex, inline code)
      println!("0x{:016x} ({} entries)", address, sym_results.len());

      for result in sym_results {
        let SymbolizedResult {symbol, start_address, path, line_no, column} = result;
        println!("    {}@0x{:016x} {}:{}", symbol, start_address, path, line_no);
      }
    } else {
      let SymbolizedResult {symbol, start_address, path, line_no, column} = &sym_results[0];
      println!("0x{:016x} {}@0x{:016x} {}:{}", address, symbol, start_address, path, line_no);
    }
  }
```

`sym_srcs` is a list of symbol sources in a process.
However, there is only one `SymbolSrcCfg::Process {}` here.
`SymbolSrcCfg::Process {}` is a convenient variant for loading all objects,
i.e., binaries and shared libraries, mapped in a process.  Therefore, developers
do not have to specify each object and its base address with
`SymbolSrcCfg::Process {}`.

`symlist` is a list of lists of `SymbolizedResult`.  The instruction provided
at an address can result from several lines of code from multiple
functions with optimization.  In other words, the result
of an address is a list of `SymbolizedResult`.  Each entry in
`symlist` results from the address at the respective position in the
argument passed to [`BlazeSymbolizer::symbolize()`].

### With Linux Kernel

`SymbolSrcCfg::Kernel {}` is a variant to load symbols of the Linux Kernel.

```rust,ignore,compile_fail
  let sym_srcs = [SymbolSrcCfg::Kernel(cfg::Kernel {
    kallsyms: Some(PathBuf::from("/proc/kallsyms")),
    kernel_image: Some(PathBuf::from("/boot/vmlinux-xxxxx")),
  })];
```

In this case, you give the path of kallsyms and the path of a kernel image.
The path of kallsyms can be that of `"/proc/"` or a copy of kallsym.

If you are symbolizing against the current running kernel on the same
device, give `None` for both paths.  Doing so will find the correct
paths for you, if possible. It will use `"/proc/kallsyms"` for
kallsyms and find the kernel image of the running kernel from several
potential directories; for instance, `"/boot/"` and `"/usr/lib/debug/boot/"`.

```rust,ignore,compile_fail
  let sym_srcs = [
    SymbolSrcCfg::Kernel(cfg::Kernel { kallsyms: None, kernel_image: None })
  ];
```

### A list of ELF files

You can still provide a list of ELF files and their base addresses if necessary.

```rust,ignore,compile_fail
  let sym_srcs = [
    SymbolSrcCfg::Elf(cfg::Elf {
      file_name: PathBuf::from("/lib/libc.so.xxx"),
      base_address: 0x1f005d,
    }),
    SymbolSrcCfg::Elf(cfg::Elf {
      fie_name: PathBuf::from("/path/to/my/binary"),
      base_address: 0x77777,
    }),
  ];
```

At the base address of an ELF file, its executable segment(s) is
loaded.

### An example of Rust API

examples/addr2ln_pid.rs is an example performing symbolization for an
address in a process.

```text
  $ ./target/debug/examples/addr2ln_pid 1234 7f0c41ade000
  PID: 1234
  0x7f0c41ade000 wcsxfrm_l@0x7f0c41addd10+752 src/foo.c:0
  $
```

The above command will display the symbol names, sources' file names,
and the line numbers of address 0x7f0c41ade000 in process 1234.

Users should build examples using the following command at the root of the
source.

```text
  $ cargo build --examples
```

## C API

The following code symbolizes a list of addresses of a process.  It
shows the addresses, symbol names, source filenames and line numbers.

```c
  #include "blazesym.h"

  struct blazesym_sym_src_cfg sym_srcs[] = {
    { BLAZESYM_SRC_T_PROCESS, .params = { .process { <pid> } } },
  };
  const struct blazesym *symbolizer;
  const struct blazesym_result * result;
  const struct blazesym_csym *sym;
  uint64_t stack[] = { 0x12345, 0x7ff992, ..};
  int stack_sz = sizeof(stack) / sizeof(stack[0]);
  uint64_t addr;
  int i, j;

  symbolizer = blazesym_new();
  /* sym_srcs should be passed every time doing symbolization */
  result = blazesym_symbolize(symbolizer,
                              sym_srcs, 1,
                              stack, stack_sz);

  for (i = 0; i < stack_sz; i++) {
    addr = stack[i];

    if (!result || i >= result->size || result->entries[i].size == 0) {
      /* not found */
      printf("[<%016llx>]\n", addr);
      continue;
    }

    if (result->entries[i].size == 1) {
      /* found one result */
      sym = &result->entries[i].syms[0];
      printf("[<%016llx>] %s@0x%llx %s:%ld\n", addr, sym->symbol, sym->start_address,
              sym->path, sym->line_no);
      continue;
    }

    /* Found multiple results */
    printf("[<%016llx>] (%d entries)\n", addr, result->entries[i].size);
    for (j = 0; j < result->entries[i].size; j++) {
      sym = &result->entries[i].syms[j];
      printf("    %s@0x$llx %s:%ld\n", sym->symbol, sym->start_address,
             sym->path, sym->line_no);
    }
  }

  blazesym_result_free(result);
  blazesym_free(symbolizer);
```

`struct blazesym_sym_src_cfg` describes a binary, symbol file, shared
object, kernel, or process. This example uses a `struct blazesym_sym_src_cfg`
instance with [`blazesym_src_type::BLAZESYM_SRC_T_PROCESS`] type to
describe a process. BlazeSym deciphers all the loaded
ELF files of the process and loads symbols and DWARF information from
them to perform symbolization.

### Link C programs

You should include `“blazesym.h”` in a C program to call
BlazeSym.  Refer to the “Build” section to generate `"blazesym.h"`.

You also need the following arguments to link against BlazeSym.

```text
  libblazesym.a -lrt -ldl -lpthread -lm
```

You may want to link a shared library, i.e., `libblazesym.so`.

### With Linux Kernel

[`blazesym_src_type::BLAZESYM_SRC_T_KERNEL`] is a variant of `struct
blazesym_sym_src_cfg` highlighting the kernel as a source of
symbolization.

```c
struct blazesym_sym_src_cfg sym_srcs[] = {
  { BLAZESYM_SRC_T_KERNEL, .params = { .kernel = { .kallsyms = "/proc/kallsyms",
                                       .kernel_image = "/boot/vmlinux-XXXXX" } } },
};
```

You can give `kallsyms` and `kernel_image` a `NULL`.  BlazeSym will
locate them for the running kernel.  For example, by default, `kallsyms`
is at `"/proc/kallsyms"`. Accordingly, the kernel image of the current
kernel will be in `"/boot/"` or `"/usr/lib/debug/boot/"`.

### A list of ELF files

The [`blazesym_src_type::BLAZESYM_SRC_T_ELF`] variant of `struct
blazesym_sym_src_cfg` provides the path of an ELF file and its base
address. You can specify a list of ELF files and where they are loaded.


```c
struct blazesym_sym_src_cfg sym_srcs[] = {
  { BLAZESYM_SRC_T_ELF, .params = { .elf = { .file_name = "/lib/libc.so.xxx",
                                    .base_address = 0x7fff31000 } } },
  { BLAZESYM_SRC_T_ELF, .params = { .elf = { .file_name = "/path/to/a/binary",
                                    .base_address = 0x1ff329000 } } },
};
```

The base address of an ELF file is where its executable segment(s) is loaded.

### An example of C API

There is an example of C API in libbpf-bootstrap.  You could view it at
<https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/profile.c>
.  This example periodically samples the running process of every processor
in a system and prints their stack traces when sampling.

## BlazeSym

BlazeSym is a library to symbolize addresses to get symbol names, file
names of source files, and line numbers.  It can translate a stack
trace to function names and their locations in the
source code.

## Build

You should install a Rust compiler and cargo to build BlazeSym.

 - cargo build

You may want to build a C header (**blazesym.h**) to include in your C programs.

 - cargo build --features="cheader"

You will find **libblazesym.a** in target/debug/ or target/release/ as
well.  Your C programs, if there are, should link against it.

**blazesym.h** is also in target/debug/ or target/release/.

## Rust APIs

The following code uses BlazeSym to get symbol names, filenames of
sources, and line numbers of addresses in a process.


```ignore
	use blazesym::{BlazeSymbolizer, SymFileCfg, SymbolizedResult};
	
	let process_id: u32 = <process id>;
    // load all symbols of loaded files of the given process.
	let cfgs = [SymFileCfg::Process { pid: process_id }];
	let symbolizer = BlazeSymbolizer::new().unwrap();

    let stack: [u64] = [0xff023, 0x17ff93b];			// Addresses of instructions
	let symlist = symbolizer.symbolize(&cfgs,			// Pass this configuration everytime.
	                                   &stack);
	for i in 0..stack.len() {
	    let address = stack[i];
		
		if symlist.len() <= i or symlist[i].len() == 0 {	// Unknown address
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

`cfgs` is a list of files loaded in a process.  However, it has only
an instance of `SymFileCfg::Process {}` here.  `SymFileCfg::Process
{}` is a convenient variant to load all objects, i.e., binaries and
shared libraries, mapped in a process.  Developers do not have to
specify every object and its loaded address with `SymFileCfg::Process {}`.

`symlist` is a list of lists of `SymbolizedResult`.  The instruction
at an address can result from several lines of code from several
functions with inlining and optimization.  In other words, the result
of an address is a list of `SymbolizedResult`.  Every entry in
`symlist` results from the address at the respective position in the
argument passed to [`BlazeSymbolizer::symbolize()`].

### With Linux Kernel

`SymFileCfg::Kernel {}` is a variant to load symbols of Linux kernel.

```ignore
	let cfgs = [SymFileCfg::Kernel {
		kallsyms: Some("/proc/kallsyms".to_string()),
		kernel_image: Some("/boot/vmlinux-xxxxx".to_string()),
	];
```

Here, you give the path of a copy of kallsyms and the path of a kernel image.

If you are symbolizing against the current running kernel on the same
device, give `None` for both paths.  It will find out the correct
paths for you if possible. It will use `"/proc/kallsyms"` for
kallsyms, and find the kernel image of running kernel from several
potential directories; ex, /boot/ and /usr/lib/debug/boot/.

```ignore
	let cfgs = [SymFileCfg::Kernel { kallsyms: None, kernel_image: None }];
```

### A list of ELF files

You can still give a list of ELF files and their loaded addresses if necessary.

```ignore
	let cfgs = [SymFileCfg::Elf { file_name: String::from("/lib/libc.so.xxx"),
	                              loaded_address: 0x1f005d },
	            SymFileCfg::Elf { fie_name: String::from("/path/to/my/binary"),
				                  loaded_address: 0x77777 },
	            ......
	];
```

### Example of Rust APIs

examples/addr2ln_pid.rs is an example doing symbolization for an
address in a process.

```ignore
    $ ./target/debug/examples/addr2ln_pid 2627679 7f0c41ade000
	PID: 2627679
	0x7f0c41ade000 wcsxfrm_l@0x7f0c41addd10+752 src/foo.c:0
	$
```

The above command will show the symbol name, the file name of the
source, and the line number of the address 0x7f0c41ade000 in the process
2627679.

Users should build examples with the following command at the root of the
source.

```ignore
    $ cargo build --examples
```

## C APIs

The Following code symbolizes a list of addresses of a process.  It
shows addresses, their symbol names, the filenames of source files,
and line numbers.

```ignore
	#include "blazesym.h"
	
	struct sym_file_cfg cfgs[] = {
		{ CFG_T_PROCESS, .params = { .process { <pid> } } },
	};
	const struct blazesym *symbolizer;
	const struct blazesym_result * result;
	const struct blazesym_csym *sym;
	uint64_t stack[] = { 0x12345, 0x7ff992, ..};
	int stack_sz = sizeof(stack) / sizeof(stack[0]);
	uint64_t addr;
	int i, j;
	
	symbolizer = blazesym_new();
	/* cfgs should be passed every time doing symbolization */
	result = blazesym_symbolize(symbolizer,
	                            cfgs, 1,
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

`struct sym_file_cfg` describes a binary, a symbol file, a shared
object, a kernel or a process.  In this example, it is with
`CFG_T_PROCESS` type to describe a process that is alive.  BlazeSym
will figure out all loaded ELF files of the process and load symbol
and DWARF information from them to perform symbolization.

### Link C programs

You should include “blazesym.h” to call BlazeSym from a C
program. Check the “Build” section to generate it.

You also need the following arguments to link against BlazeSym.

```ignore
	-lrt -ldl -lpthread -lm libblazesym.a
```

### With Linux Kernel

`CFG_T_KERNEL` variant of `struct sym_file_cfg` describes a kernel to
symbolize kernel addresses.

```ignore
	struct sym_file_cfg cfgs[] = {
		{ CFG_T_KERNEL, .params = { .kernel = { .kallsyms = "/proc/kallsyms",
		                                        .kernel_image = "/boot/vmlinux-XXXXX" } } },
	};
```

You can give `kallsyms` and `kernel_image` a `NULL`.  BlazeSym will
figure out where they are for the running kernel.  For example, by
default, `kallsyms` is at `"/proc/kallsyms"`.  The kernel image of the
current kernel will be in /boot/ or /usr/lib/debug/boot/.

### A list of ELF files

The `CFG_T_ELF` variant of `struct sym_file_cfg` gives the path of an
ELF file and its loaded address.  You can specify a list of ELF files
and where they loaded.

```ignore
	struct sym_file_cfg cfgs[] = {
		{ CFG_T_ELF, .params = { .elf = { .file_name = "/lib/libc.so.xxx",
		                                  .loaded_address = 0x7fff31000 } } },
		{ CFG_T_ELF, .params = { .elf = { .file_name = "/path/to/a/binary",
		                                  .loaded_address = 0x1ff329000 } } },
	};
```

### Example of C APIs

There is a C example in libbpf-bootstrap.  You can find it at
https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/profile.c
.  This example samples the running process of every processor
in a system periodically and prints their stack traces at the moment
doing sampling.

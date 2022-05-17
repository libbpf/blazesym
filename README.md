## BlazeSym

BlazeSym provides a solution to symbolize address in processes and
kernel.  By providing a list of addresses, it resolves these addresses
to symbol names, file names of the source, and line numbers of the
instruction.

## Build

 - cargo build

Build BlazeSym and generate a header file for C API.

 - cargo build --features="cheader"

## Examples

 ./target/{debug,release}/examples/addr2line_sym /boot/vmlinux-xxxx 0xffffffff81047cf0

The first argument is the image of currnt running kernel.  The second
argument is an address in kernel space.  You can find an address from
/proc/kallsyms.  addr2line_sym show the function name, file name, and
line number of the given address.

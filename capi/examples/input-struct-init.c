#include "blazesym.h"

int main(int argc, const char* argv[]) {
  blaze_inspect_elf_src src = {
    .type_size = sizeof(src),
    .path = "/tmp/some/dir/test.bin",
    .debug_syms = true,
  };
}

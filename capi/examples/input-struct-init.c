#include <string.h>
#include "blazesym.h"

int main(int argc, const char* argv[]) {
  BLAZE_INPUT(blaze_inspect_elf_src, src,
    .path = "/tmp/some/dir/test.bin",
    .debug_syms = true,
  );
}

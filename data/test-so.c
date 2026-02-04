#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test-so.h"

int the_answer(void) {
  return 42;
}

int the_ignored_answer(void) {
  return 43;
}

/* A static function whose symbol will be stripped from the dynamic
 * symbol table. It can only be symbolized via DWARF debug info.
 */
__attribute__((noinline)) static void *private_function(void) {
  return (void *)private_function;
}

/* Returns the address of private_function. This is exported so it can
 * be called via dlsym, but private_function itself is static and will
 * be stripped from .dynsym.
 */
void *lookup_private(void) {
  return private_function();
}

int await_input(void) {
  char buf[2];
  int rc = read(STDIN_FILENO, buf, sizeof(buf));
  if (rc < 0) {
    fprintf(stderr, "failed to read from stdin: %s\n", strerror(errno));
    return 1;
  }
  return 0;
}

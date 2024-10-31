/* A binary basically just blocking waiting for input and exiting. It also write
 * the address of its `_start` function to stdout (unformatted; just a byte
 * dump).
 *
 * It uses raw system calls to avoid dependency on libc, which pulls in
 * start up code and various other artifacts that perturb ELF layout in
 * semi-unforeseeable ways, in an attempt to provide us with maximum
 * control over the final binary.
 *
 * Likely only works on x86_64.
 */

#include <unistd.h>
#include <sys/syscall.h>


void _start(void) {
  char buf[2];
  int rc;
  void* addr = (void*)&_start;
  /* Write the address of `_start` to stderr. We use stderr because it's
     unbuffered, so we spare ourselves from the pains of writing a
     newline as well... */
  asm volatile (
      "syscall"
      : "=a"(rc)
      : "a"(SYS_write), "D"(STDERR_FILENO), "S"(&addr), "d"(sizeof(addr))
      : "rcx", "r11", "memory"
  );
  asm volatile (
      "syscall"
      : "=a"(rc)
      : "a"(SYS_read), "D"(STDIN_FILENO), "S"(buf), "d"(sizeof(buf))
      : "rcx", "r11", "memory"
  );
  if (rc > 0) {
    /* No error, so we can exit successfully. */
    rc = 0;
  }
  asm volatile (
      "syscall"
      : "=a"(rc)
      : "a"(SYS_exit), "D"(rc)
      : "rcx", "r11", "memory"
  );
}

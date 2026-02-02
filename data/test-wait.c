#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

void close_so(void **handle) {
  int rc;
  rc = dlclose(*handle);
  if (rc != 0) {
    fprintf(stderr, "warning: failed to dlclose: %s\n", dlerror());
  }
}

int main(int argc, char **argv) {
  int rc;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <path-to-libtest.so>\n",
            argc > 0 ? argv[0] : "<program>");
    return -1;
  }

  char const *libtest = argv[1];

  void *handle;
  handle = dlopen(libtest, RTLD_NOW);
  if (handle == NULL) {
    fprintf(stderr, "failed to dlopen %s: %s\n", libtest, dlerror());
    return -1;
  }
  void *_dlclose __attribute__((cleanup(close_so))) = handle;

  void *sym;
  sym = dlsym(handle, "await_input");
  if (sym == NULL) {
    fprintf(stderr, "failed to dlsym `await_input` function: %s\n", dlerror());
    return -1;
  }

  /* Write PID and address to stdout for the test harness. */
  pid_t pid = getpid();
  rc = write(STDOUT_FILENO, &pid, sizeof(pid));
  if (rc < 0) {
    perror("failed to write pid to stdout");
    return 1;
  }

  rc = write(STDOUT_FILENO, &sym, sizeof(sym));
  if (rc < 0) {
    perror("failed to write address to stdout");
    return 1;
  }

  int (*await_input)(void) = sym;
  return await_input();
}

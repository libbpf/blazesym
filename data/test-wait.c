#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

void close_so(void **handle) {
  int rc;
  rc = dlclose(*handle);
  if (rc != 0) {
    fprintf(stderr, "warning: failed to dlclose: %s\n", dlerror());
  }
}

int main(int argc, char **argv) {
  int rc;
  int err;

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

  int (*await_input)(void) = sym;
  return await_input();
}

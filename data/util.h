#ifndef UTIL_H
#define UTIL_H

#include <dlfcn.h>
#include <stdio.h>


static void close_so(void **handle) {
  int rc;
  rc = dlclose(*handle);
  if (rc != 0) {
    fprintf(stderr, "warning: failed to dlclose: %s\n", dlerror());
  }
}

#endif /* UTIL_H */

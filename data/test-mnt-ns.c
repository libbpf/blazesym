/* A binary that loads a shared object from a specified path and
 * calls the `await_input` function from that library.
 *
 * The mount namespace setup (unshare, tmpfs mount, file copy) is done
 * by the test harness via `pre_exec()`.
 *
 * Usage: test-mnt-ns <path-to-libtest.so>
 */

#include "util.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int rc;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <path-to-libtest.so>\n",
            argc > 0 ? argv[0] : "<program>");
    return 1;
  }

  char const *libtest_path = argv[1];

  void *handle;
  handle = dlopen(libtest_path, RTLD_NOW);
  if (handle == NULL) {
    fprintf(stderr, "failed to dlopen %s: %s\n", libtest_path, dlerror());
    return 1;
  }
  void *_dlclose __attribute__((cleanup(close_so))) = handle;

  int (*await_input)(void);
  await_input = dlsym(handle, "await_input");
  if (await_input == NULL) {
    fprintf(stderr, "failed to dlsym `await_input`: %s\n", dlerror());
    return 1;
  }


  /* Write PID and address to stdout for the test harness. */
  pid_t pid = getpid();
  rc = write(STDOUT_FILENO, &pid, sizeof(pid));
  if (rc < 0) {
    fprintf(stderr, "failed to write pid to stdout: %s\n", strerror(errno));
    return 1;
  }

  rc = write(STDOUT_FILENO, &await_input, sizeof(await_input));
  if (rc < 0) {
    fprintf(stderr, "failed to write address to stdout: %s\n", strerror(errno));
    return 1;
  }

  return await_input();
}

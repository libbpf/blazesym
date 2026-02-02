/* A binary that loads a shared object from a specified path,
 * chroots to a specified directory, and reports the address of a private
 * (static) function.
 *
 * The mount namespace setup (unshare, tmpfs mount, file copy) is done
 * by the test harness via `pre_exec()`.
 *
 * Usage: test-mnt-ns-dbg-link <mount-dir> <path-to-libtest.so>
 */

#include "util.h"

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int rc;

  if (argc != 3) {
    fprintf(stderr, "usage: %s <mount-dir> <path-to-libtest.so>\n",
            argc > 0 ? argv[0] : "<program>");
    return 1;
  }

  char const *mount_dir = argv[1];
  char const *libtest_path = argv[2];

  void *handle;
  handle = dlopen(libtest_path, RTLD_NOW);
  if (handle == NULL) {
    fprintf(stderr, "failed to dlopen %s: %s\n", libtest_path, dlerror());
    return 1;
  }
  void *_dlclose __attribute__((cleanup(close_so))) = handle;

  /* Change the root directory so that `/usr/lib/debug/` is now the
   * absolute path to debug information.
   */
  rc = chroot(mount_dir);
  if (rc < 0) {
    perror("failed to chroot");
    return 1;
  }

  void *(*lookup_private)(void);
  lookup_private = dlsym(handle, "lookup_private");
  if (lookup_private == NULL) {
    fprintf(stderr, "failed to dlsym `lookup_private`: %s\n", dlerror());
    return 1;
  }

  int (*await_input)(void);
  await_input = dlsym(handle, "await_input");
  if (await_input == NULL) {
    fprintf(stderr, "failed to dlsym `await_input`: %s\n", dlerror());
    return 1;
  }

  /* Get the address of the private (static) function. This symbol is
   * stripped from `.dynsym` and can only be symbolized via DWARF debug info.
   */
  void *private_addr = lookup_private();

  /* Write PID and address to stdout for the test harness. */
  pid_t pid = getpid();
  rc = write(STDOUT_FILENO, &pid, sizeof(pid));
  if (rc < 0) {
    perror("failed to write pid to stdout");
    return 1;
  }

  rc = write(STDOUT_FILENO, &private_addr, sizeof(private_addr));
  if (rc < 0) {
    perror("failed to write address to stdout");
    return 1;
  }

  return await_input();
}

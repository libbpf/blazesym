/* A binary that creates a new mount namespace and then executes
 * a specified binary with any provided arguments.
 *
 * This is a generic launcher for running programs in isolated mount
 * namespaces. The actual work is delegated to the child binary.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int rc;
  int err;

  if (argc < 2) {
    fprintf(stderr, "usage: %s <binary> [args...]\n",
            argc > 0 ? argv[0] : "<program>");
    return -1;
  }

  /* Detach ourselves from the default mount namespace, effectively
   * creating a new one for this program.
   */
  rc = unshare(CLONE_NEWNS);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "unshare failed: %s (errno: %d)\n", strerror(err), err);
    return err;
  }

  /* Execute the specified binary with the remaining arguments.
   * argv[1] is the binary path, argv[2..] are its arguments.
   * We pass &argv[1] so that argv[1] becomes argv[0] for the child.
   */
  execv(argv[1], &argv[1]);

  /* If we get here, execv failed */
  err = errno;
  fprintf(stderr, "execv failed for %s: %s (errno: %d)\n", argv[1],
          strerror(err), err);
  return err;
}

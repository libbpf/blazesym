#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

void rm_dir(char **path) {
  int rc;
  int err;

  rc = rmdir(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to remove directory %s: %s (errno: %d)\n",
            *path, strerror(err), err);
  }
}

void unmount(char **path) {
  int rc;
  int err;

  rc = umount(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to unmount %s: %s (errno: %d)\n", *path,
            strerror(err), err);
  }
}

void close_so(void **handle) {
  int rc;
  rc = dlclose(*handle);
  if (rc != 0) {
    fprintf(stderr, "warning: failed to dlclose: %s\n", dlerror());
  }
}

void rm_file(const char **path) {
  int rc;
  int err;

  rc = unlink(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to remove file %s: %s (errno: %d)\n",
            *path, strerror(err), err);
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

  char const *libtest_src = argv[1];
  /* Detach ourselves from the default mount namespace, effectively
   * creating a new one for this program.
   */
  rc = unshare(CLONE_NEWNS);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "unshare failed: %s (errno: %d)\n", strerror(err), err);
    return err;
  }

  /* Create a temporary directory (now already inside this mount
   * namespace) and mount a ramdisk in there.
   */
  char tmpl[] = "/tmp/mnt-ns.XXXXXX";
  char *dir = mkdtemp(tmpl);

  if (dir == NULL) {
    err = errno;
    fprintf(stderr, "mkdtemp failed: %s (errno: %d)\n", strerror(err), err);
    return err;
  }
  char *_rm_dir __attribute__((cleanup(rm_dir))) = dir;

  rc = mount("tmpfs", dir, "tmpfs", 0, "size=16M");
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "mount failed: %s (errno: %d)\n", strerror(err), err);
    return err;
  }
  char *_umount __attribute__((cleanup(unmount))) = dir;

  char libtest_buf[256];
  rc = snprintf(libtest_buf, sizeof(libtest_buf), "%s/libtest-so.so", dir);
  if (rc >= sizeof(libtest_buf)) {
    fprintf(
        stderr,
        "failed to construct destination path: insufficient buffer space\n");
    return -1;
  }
  libtest_buf[rc] = 0;
  char const *libtest_dst = libtest_buf;

  char cmd_buf[256];
  rc = snprintf(cmd_buf, sizeof(cmd_buf), "cp %s %s", libtest_src, libtest_dst);
  if (rc >= sizeof(cmd_buf)) {
    fprintf(stderr,
            "failed to construct cp command: insufficient buffer space\n");
    return -1;
  }
  cmd_buf[rc] = 0;

  char const *cp_cmd = cmd_buf;
  /* Sorry, not gonna put up with copying a file in C using system
   * APIs...
   */
  rc = system(cp_cmd);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "failed to copy %s to %s: %d\n", libtest_src, libtest_dst,
            rc);
    return err;
  }
  const char *_rm __attribute__((cleanup(rm_file))) = libtest_dst;

  void *handle;
  handle = dlopen(libtest_dst, RTLD_NOW);
  if (handle == NULL) {
    fprintf(stderr, "failed to dlopen %s: %s\n", libtest_dst, dlerror());
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

/* A binary that sets up a tmpfs mount, copies a shared object into it,
 * and then loads and calls the await_input function from that library.
 *
 * This is designed to be run inside a mount namespace (e.g., via
 * test-mnt-ns.bin) to test symbolization of libraries that are only
 * visible within that namespace.
 *
 * Usage: test-mnt-ns-child <path-to-libtest.so>
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
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

int copy_file(char const *src, char const *dst) {
  int src_fd = -1;
  int dst_fd = -1;
  int err;
  char buf[4096];
  ssize_t nread;
  ssize_t nwritten;
  int rc = 0;

  src_fd = open(src, O_RDONLY);
  if (src_fd < 0) {
    err = errno;
    fprintf(stderr, "failed to open %s for reading: %s (errno: %d)\n", src,
            strerror(err), err);
    return -1;
  }

  dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (dst_fd < 0) {
    err = errno;
    fprintf(stderr, "failed to open %s for writing: %s (errno: %d)\n", dst,
            strerror(err), err);
    close(src_fd);
    return -1;
  }

  while ((nread = read(src_fd, buf, sizeof(buf))) > 0) {
    char *ptr = buf;
    while (nread > 0) {
      nwritten = write(dst_fd, ptr, nread);
      if (nwritten < 0) {
        err = errno;
        fprintf(stderr, "failed to write to %s: %s (errno: %d)\n", dst,
                strerror(err), err);
        rc = -1;
        goto out;
      }
      nread -= nwritten;
      ptr += nwritten;
    }
  }

  if (nread < 0) {
    err = errno;
    fprintf(stderr, "failed to read from %s: %s (errno: %d)\n", src,
            strerror(err), err);
    rc = -1;
  }

out:
  close(src_fd);
  close(dst_fd);
  return rc;
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

  /* Create a temporary directory and mount a ramdisk in there.
   * This should be done inside a mount namespace so that the mount
   * is only visible to this process.
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

  rc = copy_file(libtest_src, libtest_dst);
  if (rc != 0) {
    return rc;
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

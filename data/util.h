#ifndef UTIL_H
#define UTIL_H

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static void rm_dir(char **path) {
  int rc;
  int err;

  rc = rmdir(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to remove directory %s: %s (errno: %d)\n",
            *path, strerror(err), err);
  }
}

static void unmount(char **path) {
  int rc;
  int err;

  rc = umount(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to unmount %s: %s (errno: %d)\n", *path,
            strerror(err), err);
  }
}

static void close_so(void **handle) {
  int rc;
  rc = dlclose(*handle);
  if (rc != 0) {
    fprintf(stderr, "warning: failed to dlclose: %s\n", dlerror());
  }
}

static void rm_file(const char **path) {
  int rc;
  int err;

  rc = unlink(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to remove file %s: %s (errno: %d)\n",
            *path, strerror(err), err);
  }
}

static int copy_file(char const *src, char const *dst) {
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

#endif /* UTIL_H */

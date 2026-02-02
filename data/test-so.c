#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

#include "test-so.h"

int the_answer(void) {
  return 42;
}

int the_ignored_answer(void) {
  return 43;
}

int await_input(void) {
  pid_t pid = getpid();
  int rc = write(STDOUT_FILENO, &pid, sizeof(pid));
  if (rc < 0) {
    perror("failed to write pid to stdout");
    return 1;
  }

  void* addr = (void*)&await_input;
  rc = write(STDOUT_FILENO, &addr, sizeof(addr));
  if (rc < 0) {
    perror("failed to write address to stdout");
    return 1;
  }

  char buf[2];
  rc = read(STDIN_FILENO, buf, sizeof(buf));
  if (rc < 0) {
    perror("failed to read from stdin");
    return 1;
  }
  return 0;
}

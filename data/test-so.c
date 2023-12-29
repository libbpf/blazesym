#include <stdio.h>
#include <time.h>

int the_answer(void) {
  return 42;
}

int await_input(void) {
  struct timespec ts = {.tv_sec = 60};

  fprintf(stdout, "%p\n", &await_input);
  fflush(stdout);

  int c;
  c = getc(stdin);
  return 0;
}

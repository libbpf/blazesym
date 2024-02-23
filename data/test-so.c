#include <stdio.h>

#include "test-so.h"

int the_answer(void) {
  return 42;
}

int the_ignored_answer(void) {
  return 43;
}

int await_input(void) {
  fprintf(stdout, "%p\n", &await_input);
  fflush(stdout);

  int c;
  c = getc(stdin);
  return 0;
}

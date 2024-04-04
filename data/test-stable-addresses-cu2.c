extern unsigned int factorial(unsigned int n);
extern volatile char a_variable[8];

__attribute__((noinline)) static void
factorial_wrapper() {
	factorial(5);
}

__attribute__((noinline)) static void i_exist_twice(void) {
  a_variable[0] = '\0';
}

void foo(void) {
	factorial_wrapper();
  i_exist_twice();
}

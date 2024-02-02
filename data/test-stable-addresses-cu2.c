extern unsigned int factorial(unsigned int n);
extern volatile char a_variable[8];

__attribute__((noinline)) static void i_exist_twice(void) {
  a_variable[0] = '\0';
}

__attribute__((noinline)) static void
factorial_wrapper() {
	factorial(5);
}

void foo(void) {
	factorial_wrapper();
}

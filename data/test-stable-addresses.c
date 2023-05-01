/* The sample program is used to generate test.gsym.
 *
 * Chosen functions are placed in dedicated sections to allow for control placement.
 */
extern void foo(void);

__attribute__((section(".text.factorial"))) unsigned int
factorial(unsigned int n) {
	if (n == 0)
		return 1;
	return factorial(n - 1) * n;
}

__attribute__((noinline)) static void
factorial_wrapper() {
	factorial(5);
}

__attribute__((section(".text.main"))) int
main(int argc, const char *argv[]) {
	factorial_wrapper();
	foo();
	return 0;
}

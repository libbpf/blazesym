/*
 * The sample program is used to generate test.gsym.
 *
 * This sample need to build with the following instructions.
 *  - gcc -gdwarf -O -o gsym-factorial.o -DFACTORIAL_ALONE -c data/gsym-example.c
 *  - gcc -gdwarf -O -fno-toplevel-reorder -c data/gsym-example.c
 *  - gcc -gdwarf -T data/gsym-example.ld -O -nostdlib -o gsym gsym-example.o gsym-factorial.o
 *  - llvm-gsymutil --convert=gsym  --out-file data/test.gsym
 *
 * `-nostdlib` stops the linker to introduce symbols from libc and
 * crt*.o, that will make linker script even more complicated and
 * platform dependent.  Without stdlib, it means we can not call
 * functions provided by libc and other libraries in our samples.
 *
 * In order to ensure the output binary is runnable (at least with
 * most Linux distro) without stdlib, the main function should be
 * placed at the first place of the object file (or define the entry
 * point), and add `-fno-toplevel-reorder` to ensure the order.
 * Otherwise, we also want the main fucntion at a fixed location.
 * Clang seems to have different options for this purpose.
 *
 * `fibbonacci()` is compiled separate to generate a separate object
 * file so that it can be relocated manually.
 *
 * We also has a linker script, `data/gsym-example.ld`, to help
 * relocation.  It is fragile due to different configurations,
 * platforms, and versions of toolchains.  Some platform may introduce
 * additional unexpected sections or data. These unexpected data will
 * affect the relocation.  We can get rid of these uncertains by with
 * a custom toolchain.  However, it is overkilled.
 *
 * The recipe is fragile due to the differences between toolchains and
 * versions.
 */
#ifdef FACTORIAL_ALONE

unsigned int factorial(unsigned int n) {
	if (n == 0)
		return 1;
	return factorial(n - 1) * n;
}

#else

extern unsigned int fibbonacci(unsigned int);
extern unsigned int factorial(unsigned int n);

static
inline void factorial_inline_wrapper() {
	factorial(5);
}

int
main(int argc, const char *argv[]) {
	int i;

	factorial_inline_wrapper();
	for (i = 0; i < 100; i++) {
		fibbonacci(i);
	}
	return 0;
}

unsigned int fibbonacci(unsigned int n) {
	if (n <= 1)
		return n;
	return fibbonacci(n - 1) + fibbonacci(n - 2);
}

#endif

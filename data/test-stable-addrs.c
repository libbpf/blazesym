/* The sample program is used to generate test-stable-addrs*.
 *
 * Chosen functions are placed in dedicated sections to allow for control placement.
 */
extern void foo(void);

__attribute__((section(".data.var"))) volatile char a_variable[8];

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

__attribute__((always_inline)) static void
factorial_2nd_layer_inline_wrapper() {
  factorial(6);
}

__attribute__((always_inline)) static void
factorial_inline_wrapper() {
  factorial_2nd_layer_inline_wrapper();
}

__attribute__((section(".text.inline")))
__attribute__((noinline)) static void
factorial_inline_test() {
  factorial_inline_wrapper();
}

void my_indirect_func(void) {
}

static void (*resolve_indirect_func(void))(void) {
  return my_indirect_func;
}

void indirect_func(void) __attribute__ ((ifunc ("resolve_indirect_func")));

__attribute__((noinline)) static void i_exist_twice(void) {
  a_variable[1] = '\0';
}

// A dummy function that should not actually be called. It just contains a bunch
// of signature bytes that we use for offset verification later on.
asm(
  ".globl dummy\n"
  ".type dummy, @function\n"
  "dummy:\n"
  ".byte 0xde\n"
  ".byte 0xad\n"
  ".byte 0xbe\n"
  ".byte 0xef\n"
);

extern void dummy(void);

asm(
  ".globl untyped\n"
  "untyped:\n"
  "nop\n"
  "nop\n"
);
extern void untyped(void);

// It's possible to control section placement via `.pushsection` command,
// which would allow for precise address control. However, gsym conversion
// ignored the symbol in this case. Play it safe and don't specify the section.
asm(
  ".globl zero_size\n"
  ".type zero_size, @function\n"
  "zero_size:\n"
);
extern void zero_size(void);

__attribute__((section(".text.main"))) int
main(int argc, const char *argv[]) {
  factorial_wrapper();
  factorial_inline_test();
  foo();
  dummy();
  i_exist_twice();
  zero_size();
  untyped();

  a_variable[0] = 42;
  return 0;
}

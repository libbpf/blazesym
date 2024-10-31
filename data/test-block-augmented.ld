/* Linker script meant to augment the default one and insert some
 * fill bytes at a relatively low address (hopefully before any of the
 * regular relevant code. */

SECTIONS {
  .whatevs (0x100000): {
    FILL(0xdead)
    . = ABSOLUTE(. + 0x300000);
  }
}

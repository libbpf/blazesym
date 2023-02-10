SECTIONS {
  .text (0x2000000) : {
    *(.text.main)
    *(.text)
    . = ABSOLUTE(0x2000100);
    *(.text.factorial)
  }
  .data : {
    *(.data)
  }
  .bss : {
    *(.bss)
  }

  /DISCARD/ : {
    *(.*)
  }
}

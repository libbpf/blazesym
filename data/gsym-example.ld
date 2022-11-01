SECTIONS {
	. = 0x1000000;
	/* The some toolchain may introduce additional sections here. Without the following line,
         * the .text section will follow these sections and be located at an unknown address.
         */
	. = 0x2000000;
	.text : {
	      :gsym-example.o(.text)
	      . = 0x20000;
	      :gsym-factorial.o(.text)
	}
	.data : {
	      *(.data)
	}
	.bss : {
	     *(.bss)
	 }
}

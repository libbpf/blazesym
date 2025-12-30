package blazesym_test

import (
	"fmt"
	"log"

	blazesym "github.com/libbpf/blazesym/go"
)

func ExampleElfSource() {
	symbolizer, err := blazesym.NewSymbolizer()
	if err != nil {
		log.Fatalf("error creating symbolizer: %v", err)
	}

	symbols, err := symbolizer.SymbolizeElfVirtOffsets(&blazesym.ElfSource{Path: "../data/test-stable-addrs-compressed-debug-zlib.bin", DebugSyms: true}, []uint64{0x2000200})
	if err != nil {
		log.Fatalf("error symbolizing: %v", err)
	}

	fmt.Printf("%s @ 0x%x %s\n", symbols[0].Name, symbols[0].Addr, symbols[0].CodeInfo.File)
	// Output: factorial @ 0x2000200 test-stable-addrs.c
}

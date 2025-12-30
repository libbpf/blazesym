package blazesym

/*
#include "blazesym.h"
*/
import "C"

import "unsafe"

// ElfSource described the parameters to load symbols and debug information from an ELF.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_elf.html
type ElfSource struct {
	// The path to an ELF file.
	Path string
	// Whether or not to consult debug symbols to satisfy the request (if present).
	DebugSyms bool
}

func (s *ElfSource) toCStruct() *C.struct_blaze_symbolize_src_elf {
	elf := C.struct_blaze_symbolize_src_elf{}
	elf.type_size = C.ulong(unsafe.Sizeof(elf))
	elf.path = C.CString(s.Path)
	elf.debug_syms = C.bool(s.DebugSyms)
	return &elf
}

func cleanupElfSourceStruct(elf *C.struct_blaze_symbolize_src_elf) {
	C.free(unsafe.Pointer(elf.path))
}

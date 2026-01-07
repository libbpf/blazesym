package blazesym

/*
#include "blazesym.h"
*/
import "C"

import "unsafe"

// ElfSource describes the parameters to load symbols and debug information from an ELF.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_elf.html
type ElfSource struct {
	source C.struct_blaze_symbolize_src_elf
}

// newElfSource creates a new elf source with the path to the ELF file.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_elf.html#structfield.path
func newElfSource(path string) *ElfSource {
	source := C.struct_blaze_symbolize_src_elf{}
	source.type_size = C.ulong(unsafe.Sizeof(source))
	source.path = C.CString(path)
	return &ElfSource{source: source}
}

// ElfSourceOption configures ElfSource objects.
type ElfSourceOption func(*ElfSource)

// ElfSourceWithDebugSyms configures whether or not to consult debug symbols to satisfy the request (if present).
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_elf.html#structfield.debug_syms
func ElfSourceWithDebugSyms(enabled bool) ElfSourceOption {
	return func(es *ElfSource) {
		es.source.debug_syms = C.bool(enabled)
	}
}

func cleanupElfSourceStruct(elf *C.struct_blaze_symbolize_src_elf) {
	C.free(unsafe.Pointer(elf.path))
}

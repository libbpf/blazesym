package blazesym

/*
#include "blazesym.h"
*/
import "C"

import "unsafe"

// GsymFileSource describes the parameters to load symbols and debug information from a Gsym file.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_gsym_file.html
type GsymFileSource struct {
	source C.blaze_symbolize_src_gsym_file
}

// newGsymFileSource creates a new gsym file source with the path to the Gsym file.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_gsym_file.html#structfield.path
func newGsymFileSource(path string) *GsymFileSource {
	source := C.blaze_symbolize_src_gsym_file{}
	source.type_size = C.ulong(unsafe.Sizeof(source))
	source.path = C.CString(path)
	return &GsymFileSource{source: source}
}

func cleanupGsymFileSourceStruct(gsym *C.blaze_symbolize_src_gsym_file) {
	C.free(unsafe.Pointer(gsym.path))
}

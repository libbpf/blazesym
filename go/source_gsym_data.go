package blazesym

/*
#include "blazesym.h"
*/
import "C"

import (
	"unsafe"
)

// GsymDataSource describes the parameters to load symbols and debug information from “raw” Gsym data.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_gsym_data.html
type GsymDataSource struct {
	source C.blaze_symbolize_src_gsym_data
}

// newGsymDataSource creates a new gsym data source with the raw Gsym data.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_gsym_data.html#structfield.data
func newGsymDataSource(data []byte) *GsymDataSource {
	source := C.blaze_symbolize_src_gsym_data{}
	source.type_size = C.ulong(unsafe.Sizeof(source))
	source.data = (*C.uchar)(unsafe.Pointer(&data[0]))
	source.data_len = C.size_t(len(data))
	return &GsymDataSource{source: source}
}

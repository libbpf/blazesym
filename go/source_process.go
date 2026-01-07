package blazesym

/*
#include "blazesym.h"
*/
import "C"

import "unsafe"

// ProcessSource describes the parameters to load symbols and debug information from a process.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html
type ProcessSource struct {
	source C.struct_blaze_symbolize_src_process
}

// newProcessSource creates a new process source with the referenced process’ ID.
// https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html#structfield.pid
func newProcessSource(pid uint32) *ProcessSource {
	source := C.struct_blaze_symbolize_src_process{}
	source.type_size = C.ulong(unsafe.Sizeof(source))
	source.pid = C.uint32_t(pid)
	return &ProcessSource{source: source}
}

// ProcessSourceOption configures ProcessSource objects.
type ProcessSourceOption func(*ProcessSource)

// ProcessSourceWithDebugSyms configures whether or not to consult debug symbols to satisfy the request (if present).
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html#structfield.debug_syms
func ProcessSourceWithDebugSyms(enabled bool) ProcessSourceOption {
	return func(ps *ProcessSource) {
		ps.source.debug_syms = C.bool(enabled)
	}
}

// ProcessSourceWithPerfMap configures whether to incorporate a process’ perf map file into the symbolization procedure.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html#structfield.perf_map
func ProcessSourceWithPerfMap(enabled bool) ProcessSourceOption {
	return func(ps *ProcessSource) {
		ps.source.perf_map = C.bool(enabled)
	}
}

// ProcessSourceWithoutMapFiles configures whether to work with /proc/<pid>/map_files/ entries or with symbolic paths mentioned in /proc/<pid>/maps instead.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html#structfield.no_map_files
func ProcessSourceWithoutMapFiles(enabled bool) ProcessSourceOption {
	return func(ps *ProcessSource) {
		ps.source.no_map_files = C.bool(enabled)
	}
}

// ProcessSourceWithoutVDSO configures whether or not to symbolize addresses in a vDSO (virtual dynamic shared object).
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html#structfield.no_vdso
func ProcessSourceWithoutVDSO(enabled bool) ProcessSourceOption {
	return func(ps *ProcessSource) {
		ps.source.no_vdso = C.bool(enabled)
	}
}

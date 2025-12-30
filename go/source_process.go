package blazesym

/*
#include "blazesym.h"
*/
import "C"
import "unsafe"

// ProcessSource describes the parameters to load symbols and debug information from a process.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_src_process.html
type ProcessSource struct {
	// The referenced process’ ID.
	Pid uint32
	// Whether or not to consult debug symbols to satisfy the request (if present).
	DebugSyms bool
	// Whether to incorporate a process’ perf map file into the symbolization procedure.
	PerfMap bool
	// Whether to work with /proc/<pid>/map_files/ entries or with symbolic paths mentioned in /proc/<pid>/maps instead.
	NoMapFiles bool
	// Whether or not to symbolize addresses in a vDSO (virtual dynamic shared object).
	NoVdso bool
}

func (s *ProcessSource) toCStruct() *C.struct_blaze_symbolize_src_process {
	process := C.struct_blaze_symbolize_src_process{}
	process.type_size = C.ulong(unsafe.Sizeof(process))
	process.pid = C.uint32_t(s.Pid)
	process.debug_syms = C.bool(s.DebugSyms)
	process.perf_map = C.bool(s.PerfMap)
	process.no_map_files = C.bool(s.NoMapFiles)
	process.no_vdso = C.bool(s.NoVdso)
	return &process
}

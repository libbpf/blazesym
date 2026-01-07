package blazesym

/*
#cgo LDFLAGS: -lblazesym_c
#include "blazesym.h"
*/
import "C"

import (
	"unsafe"
)

// SymbolizerOptions is options for configuring Symbolizer objects.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolizer_opts.html
type SymbolizerOptions struct {
	opts C.blaze_symbolizer_opts
}

func newSymbolizerOptions() *SymbolizerOptions {
	opts := C.blaze_symbolizer_opts{}
	opts.type_size = C.ulong(unsafe.Sizeof(opts))
	opts.auto_reload = C.bool(true)
	opts.code_info = C.bool(true)
	opts.inlined_fns = C.bool(true)
	opts.demangle = C.bool(true)

	return &SymbolizerOptions{opts: opts}
}

// Close frees resources associated with SymbolizerOptions.
func (so *SymbolizerOptions) Close() {
	freeCArrayOfStrings(so.opts.debug_dirs, so.opts.debug_dirs_len)
}

// SymbolizerOption configures SymbolizerOptions objects.
type SymbolizerOption func(*SymbolizerOptions)

// SymbolizerWithDebugDirs sets the array of debug directories to search for split debug information.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolizer_opts.html#structfield.debug_dirs
func SymbolizerWithDebugDirs(dirs []string) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		if so.opts.debug_dirs_len != 0 {
			freeCArrayOfStrings(so.opts.debug_dirs, so.opts.debug_dirs_len)
		}

		so.opts.debug_dirs = makeCArrayOfStrings(dirs)
		so.opts.debug_dirs_len = C.size_t(len(dirs))
	}
}

// SymbolizerWithAutoReload sets whether or not to automatically reload file system based
// symbolization sources that were updated since the last symbolization operation.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolizer_opts.html#structfield.auto_reload
func SymbolizerWithAutoReload(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.auto_reload = C.bool(enabled)
	}
}

// SymbolizerWithCodeInfo sets whether to attempt to gather source code location information.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolizer_opts.html#structfield.code_info
func SymbolizerWithCodeInfo(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.code_info = C.bool(enabled)
	}
}

// SymbolizerWithInlinedFns sets whether to report inlined functions as part of symbolization.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolizer_opts.html#structfield.inlined_fns
func SymbolizerWithInlinedFns(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.inlined_fns = C.bool(enabled)
	}
}

// SymbolizerWithDemangle sets whether or not to transparently demangle symbols.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolizer_opts.html#structfield.demangle
func SymbolizerWithDemangle(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.demangle = C.bool(enabled)
	}
}

func makeCArrayOfStrings(input []string) **C.char {
	arr := C.malloc(C.size_t(len(input)) * C.size_t(unsafe.Sizeof(uintptr(0))))

	pointers := unsafe.Slice((**C.char)(arr), len(input))

	for i, s := range input {
		pointers[i] = C.CString(s)
	}

	return (**C.char)(arr)
}

func freeCArrayOfStrings(input **C.char, length C.size_t) {
	if length == 0 {
		return
	}

	pointers := unsafe.Slice(input, length)

	for i := range length {
		C.free(unsafe.Pointer(pointers[i]))
	}

	C.free(unsafe.Pointer(input))
}

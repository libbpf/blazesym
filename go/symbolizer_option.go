package blazesym

/*
#cgo LDFLAGS: -lblazesym_c
#include "blazesym.h"
*/
import "C"

import (
	"unsafe"
)

var defaultDebugDirs = []string{"/usr/lib/debug", "/lib/debug/"}

type SymbolizerOptions struct {
	opts C.blaze_symbolizer_opts
}

func newSymbolizerOptions() *SymbolizerOptions {
	opts := C.blaze_symbolizer_opts{}
	opts.type_size = C.ulong(unsafe.Sizeof(opts))
	opts.debug_dirs = makeCArrayOfStrings(defaultDebugDirs)
	opts.debug_dirs_len = C.size_t(len(defaultDebugDirs))
	opts.auto_reload = C.bool(true)
	opts.code_info = C.bool(true)
	opts.inlined_fns = C.bool(true)
	opts.demangle = C.bool(true)

	return &SymbolizerOptions{opts: opts}
}

func (so *SymbolizerOptions) Close() {
	freeCArrayOfStrings(so.opts.debug_dirs, so.opts.debug_dirs_len)
}

type SymbolizerOption func(*SymbolizerOptions)

func WithDebugDirs(dirs []string) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		if so.opts.debug_dirs_len != 0 {
			freeCArrayOfStrings(so.opts.debug_dirs, so.opts.debug_dirs_len)
		}

		so.opts.debug_dirs = makeCArrayOfStrings(dirs)
		so.opts.debug_dirs_len = C.size_t(len(dirs))
	}
}

func WithAutoReload(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.auto_reload = C.bool(enabled)
	}
}

func WithCodeInfo(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.code_info = C.bool(enabled)
	}
}

func WithInlinedFns(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.inlined_fns = C.bool(enabled)
	}
}

func WithDemangle(enabled bool) SymbolizerOption {
	return func(so *SymbolizerOptions) {
		so.opts.demangle = C.bool(enabled)
	}
}

func makeCArrayOfStrings(input []string) **C.char {
	arr := C.malloc(C.size_t(len(input)) * C.size_t(unsafe.Sizeof(uintptr(0))))

	pointers := (*[1<<30 - 1]*C.char)(arr)

	for i, s := range input {
		pointers[i] = C.CString(s)
	}

	return (**C.char)(arr)
}

func freeCArrayOfStrings(input **C.char, length C.size_t) {
	if length == 0 {
		return
	}

	pointers := (*[1<<30 - 1]*C.char)(unsafe.Pointer(input))

	for i := range length {
		C.free(unsafe.Pointer(pointers[i]))
	}

	C.free(unsafe.Pointer(input))
}

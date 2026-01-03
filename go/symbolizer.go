package blazesym

import (
	"unsafe"
)

/*
#cgo LDFLAGS: -lblazesym_c
#include "blazesym.h"

// Adding a C function to return syms from blaze_result
struct blaze_sym* get_result(blaze_syms* res, size_t pos) {
	return &res->syms[pos];
}
*/
import "C"

// Symbolizer represents a Blazesym symbolizer.
type Symbolizer struct {
	s *C.blaze_symbolizer
}

// NewSymbolizer creates an instance of a symbolizer.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/fn.blaze_symbolizer_new.html
func NewSymbolizer(options ...SymbolizerOption) (*Symbolizer, error) {
	so := newSymbolizerOptions()
	defer so.Close()

	for _, option := range options {
		option(so)
	}

	s := C.blaze_symbolizer_new_opts(&so.opts)
	if s == nil {
		return nil, blazeErr(C.blaze_err_last()).Error()
	}

	return &Symbolizer{s: s}, nil
}

// Close closes the a symbolizer.
func (s *Symbolizer) Close() {
	C.blaze_symbolizer_free(s.s)
}

// SymbolizeElfVirtOffsets symbolizes virtual offsets in an ELF file.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/fn.blaze_symbolize_elf_virt_offsets.html
func (s *Symbolizer) SymbolizeElfVirtOffsets(source *ElfSource, input []uint64) ([]Sym, error) {
	elf := source.toCStruct()
	defer cleanupElfSourceStruct(elf)

	caddr, clen := addrsToPtr(input)

	return s.processSyms(C.blaze_symbolize_elf_virt_offsets(s.s, elf, caddr, clen), input)
}

// SymbolizeProcessAbsAddrs symbolizes a list of process absolute addresses.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/fn.blaze_symbolize_process_abs_addrs.html
func (s *Symbolizer) SymbolizeProcessAbsAddrs(source *ProcessSource, input []uint64) ([]Sym, error) {
	process := source.toCStruct()

	caddr, clen := addrsToPtr(input)

	return s.processSyms(C.blaze_symbolize_process_abs_addrs(s.s, process, caddr, clen), input)
}

func (s *Symbolizer) processSyms(syms *C.blaze_syms, input []uint64) ([]Sym, error) {
	lastErr := blazeErr(C.blaze_err_last())
	if lastErr != blazeErrOk {
		return nil, lastErr.Error()
	}

	// this should not happen, but we make sure to not call blaze_syms_free for nothing
	if syms == nil {
		return nil, nil
	}

	defer C.blaze_syms_free(syms)

	results := make([]Sym, syms.cnt)
	for i := 0; i < int(syms.cnt); i++ {
		sym := C.get_result(syms, C.size_t(i))

		results[i].Name = C.GoString(sym.name)
		results[i].Module = C.GoString(sym.module)
		results[i].Addr = uint64(sym.addr)
		results[i].Offset = uint64(sym.offset)
		results[i].Size = int64(sym.size)

		if sym.code_info.file != nil {
			results[i].CodeInfo = &CodeInfo{
				Dir:    C.GoString(sym.code_info.dir),
				File:   C.GoString(sym.code_info.file),
				Line:   uint32(sym.code_info.line),
				Column: uint16(sym.code_info.column),
			}
		}

		results[i].Inlined = make([]InlinedFn, sym.inlined_cnt)

		if sym.inlined_cnt > 0 {
			inlined := (*[1 << 30]C.blaze_symbolize_inlined_fn)(unsafe.Pointer(sym.inlined))[:sym.inlined_cnt:sym.inlined_cnt]

			for j := 0; j < int(sym.inlined_cnt); j++ {
				results[i].Inlined[j].Name = C.GoString(inlined[j].name)

				if inlined[j].code_info.file != nil {
					results[i].Inlined[j].CodeInfo = &CodeInfo{
						Dir:    C.GoString(inlined[j].code_info.dir),
						File:   C.GoString(inlined[j].code_info.file),
						Line:   uint32(inlined[j].code_info.line),
						Column: uint16(inlined[j].code_info.column),
					}
				}
			}
		}

		results[i].Reason = SymbolizeReason(sym.reason)
	}

	return results, nil
}

func addrsToPtr(input []uint64) (*C.uint64_t, C.size_t) {
	var result *C.uint64_t
	length := len(input)
	if length > 0 {
		result = (*C.uint64_t)(unsafe.Pointer(&input[0]))
	}
	return result, C.size_t(length)
}

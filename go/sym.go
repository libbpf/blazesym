package blazesym

// Sym is the result of address symbolization by Symbolizer.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_sym.html
type Sym struct {
	// The symbol name that an address belongs to.
	Name string
	// The path to or name of the module containing the symbol.
	Module string
	// The address at which the symbol is located (i.e., its “start”).
	Addr uint64
	// The byte offset of the address that got symbolized from the start of the symbol (i.e., from addr).
	Offset uint64
	// The symbol's size, if available.
	Size int64
	// Source code location information for the symbol.
	CodeInfo *CodeInfo
	// Inlined function information, if requested and available.
	Inlined []InlinedFn
	// On error (i.e., if name is NULL), a reason trying to explain why symbolization failed.
	Reason SymbolizeReason
}

// CodeInfo describes source code location information for a symbol or inlined function.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_code_info.html
type CodeInfo struct {
	// The directory in which the source file resides.
	Dir string
	// The file that defines the symbol.
	File string
	// The line number of the symbolized instruction in the source code.
	Line uint32
	// The column number of the symbolized instruction in the source code.
	Column uint16
}

// InlinedFn represents an inlined function.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_inlined_fn.html
type InlinedFn struct {
	// The symbol name of the inlined function.
	Name string
	// Source code location information for the call to the function.
	CodeInfo *CodeInfo
}

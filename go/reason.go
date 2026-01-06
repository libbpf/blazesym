package blazesym

// SymbolizeReason describes the reason why symbolization failed.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_symbolize_reason.html
type SymbolizeReason int

const (
	// SymbolizeReasonSuccess means that symbolization was successful.
	SymbolizeReasonSuccess SymbolizeReason = 0
	// SymbolizeReasonUnmapped means that the absolute address was not found
	// in the corresponding process' virtual memory map.
	SymbolizeReasonUnmapped SymbolizeReason = 1
	// SymbolizeReasonInvalidFileOffset means that the file offset does not map
	// to a valid piece of code/data.
	SymbolizeReasonInvalidFileOffset SymbolizeReason = 2
	// SymbolizeReasonMissingComponent means that the `/proc/<pid>/maps` entry
	// corresponding to the address does not have a component (file system path,
	// object, ...) associated with it.
	SymbolizeReasonMissingComponent SymbolizeReason = 3
	// SymbolizeReasonMissingSyms means that the symbolization source has no
	// or no relevant symbols.
	SymbolizeReasonMissingSyms SymbolizeReason = 4
	// SymbolizeReasonUnknownAddr means that the address could not be found
	// in the symbolization source.
	SymbolizeReasonUnknownAddr SymbolizeReason = 5
	// SymbolizeReasonUnsupported means that the address belonged to an entity
	// that is currently unsupported.
	SymbolizeReasonUnsupported SymbolizeReason = 6
)

package blazesym

import "errors"

/*
#cgo LDFLAGS: -lblazesym_c
#include "blazesym.h"
*/
import "C"

// blazeErr is an enum providing a rough classification of errors.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/struct.blaze_err.html
type blazeErr int

const (
	// The operation was successful.
	blazeErrOk blazeErr = 0
	// An entity was not found, often a file.
	blazeErrNotFound blazeErr = -2
	// The operation lacked the necessary privileges to complete.
	blazeErrPermissionDenied blazeErr = -1
	// An entity already exists, often a file.
	blazeErrAlreadyExists blazeErr = -17
	// The operation needs to block to complete, but the blocking operation was requested to not occur.
	blazeErrWouldBlock blazeErr = -11
	// Data not valid for the operation were encountered.
	blazeErrInvalidData blazeErr = -22
	// The I/O operation’s timeout expired, causing it to be canceled.
	blazeErrTimedOut blazeErr = -110
	// This operation is unsupported on this platform.
	blazeErrUnsupported blazeErr = -95
	// An operation could not be completed, because it failed to allocate enough memory.
	blazeErrOutOfMemory blazeErr = -12
	// A parameter was incorrect.
	blazeErrInvalidInput blazeErr = -256
	// An error returned when an operation could not be completed because a call to write returned Ok(0).
	blazeErrWriteZero blazeErr = -257
	// An error returned when an operation would not be completed because an “end of file” was reached prematurely.
	blazeErrUnexpectedEOF blazeErr = -258
	// DWARF input data was invalid.
	blazeErrInvalidDwarf blazeErr = -259
	// A custom error that does not fall under any other I/O error kind.
	blazeErrOther blazeErr = -260
)

// Error returns an error representation of a blazesym error.
// See: https://docs.rs/blazesym-c/latest/blazesym_c/fn.blaze_err_str.html
func (e blazeErr) Error() error {
	return errors.New(C.GoString(C.blaze_err_str(C.blaze_err(e))))
}

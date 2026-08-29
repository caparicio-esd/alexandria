package wallet

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound reports that a referenced entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict reports that the operation collides with existing state.
	ErrConflict = errors.New("conflict")
	// ErrInvalidInput reports that the caller supplied unusable arguments.
	ErrInvalidInput = errors.New("invalid input")
	// ErrNotLinked reports that the wallet is not registered in the directory.
	ErrNotLinked = errors.New("wallet is not linked")
	// ErrUnsupported reports that the request names a capability this build
	// does not implement.
	ErrUnsupported = errors.New("unsupported")
)

// ValidationError pinpoints the offending field of an invalid request, so a
// driving adapter can render a field-level message without parsing strings.
type ValidationError struct {
	Field  string
	Reason string
}

// Error implements error.
func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

// Is makes every ValidationError match ErrInvalidInput, so adapters can handle
// the whole class with a single errors.Is.
func (e ValidationError) Is(target error) bool { return target == ErrInvalidInput }

// invalid is the shorthand used across the use cases.
func invalid(field, reason string) error {
	return ValidationError{Field: field, Reason: reason}
}

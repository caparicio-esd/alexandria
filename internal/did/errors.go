package did

import (
	"errors"
	"fmt"
)

// Errors reported by this package. They describe spec-level violations only;
// callers translate them into the vocabulary of their own bounded context.
var (
	// ErrMalformed reports a DID string or component that does not parse.
	ErrMalformed = errors.New("malformed did")
	// ErrUnsupportedMethod reports a DID method this build cannot handle.
	ErrUnsupportedMethod = errors.New("unsupported did method")
)

// ServiceError pinpoints the offending service entry of a DID Document.
//
// It carries the index and the component rather than a rendered field path,
// because the path a client sees is the caller's wire vocabulary, not ours.
type ServiceError struct {
	Index     int
	Component string
	Reason    string
}

// Error implements error.
func (e ServiceError) Error() string {
	return fmt.Sprintf("service[%d].%s: %s", e.Index, e.Component, e.Reason)
}

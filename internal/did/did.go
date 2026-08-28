// Package did implements the W3C Decentralized Identifier types shared by every
// bounded context: the identifier itself, its document, and the derivation rules
// of the supported methods.
//
// It is a shared kernel. It holds no ownership concepts — no alias, no default
// key, no timestamps — because those belong to whichever context owns a given
// DID. It imports no transport, no persistence and no other domain package.
package did

import (
	"fmt"
	"strings"
)

// DID is a parsed Decentralized Identifier.
type DID struct {
	Method Method
	// ID is the method-specific identifier, e.g. "example.org:alice".
	ID string
}

// String renders the canonical did:<method>:<id> form.
func (d DID) String() string {
	if d.IsZero() {
		return ""
	}

	return "did:" + string(d.Method) + ":" + d.ID
}

// IsZero reports whether the identifier is unset.
func (d DID) IsZero() bool { return d.Method == "" || d.ID == "" }

// Fragment renders a DID URL pointing at a component of the document.
func (d DID) Fragment(name string) string {
	return d.String() + "#" + name
}

// Parse reads the canonical form, rejecting unknown methods.
func Parse(s string) (DID, error) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 3)
	if len(parts) != 3 || parts[0] != "did" || parts[1] == "" || parts[2] == "" {
		return DID{}, fmt.Errorf("%w: %q is not a did:<method>:<id>", ErrMalformed, s)
	}

	method := Method(parts[1])
	if !method.IsSupported() {
		return DID{}, fmt.Errorf("%w: %q", ErrUnsupportedMethod, method)
	}

	return DID{Method: method, ID: parts[2]}, nil
}

// NewWeb derives a did:web from a bare DNS name and an optional path.
func NewWeb(domain, path string) (DID, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return DID{}, fmt.Errorf("%w: did:web requires a domain", ErrMalformed)
	}

	if strings.ContainsAny(domain, "/: ") {
		return DID{}, fmt.Errorf(
			"%w: must be a bare DNS name, without scheme, port or path", ErrMalformed)
	}

	id := domain
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg != "" {
			id += ":" + seg
		}
	}

	return DID{Method: MethodWeb, ID: id}, nil
}

// NewKey derives a did:key from encoded public key material.
//
// TODO: the spec derives the identifier from the multicodec-prefixed public key
// in multibase. Callers currently pass a key thumbprint as a placeholder, which
// yields a stable but non-interoperable identifier.
func NewKey(encoded string) (DID, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return DID{}, fmt.Errorf("%w: did:key requires encoded key material", ErrMalformed)
	}

	return DID{Method: MethodKey, ID: encoded}, nil
}

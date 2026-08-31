// Package common holds the vocabulary the bounded contexts of this project
// share: the DID methods, the recipes for minting one, the service entries a
// DID Document publishes, and the error sentinels adapters branch on.
//
// It is a shared kernel, not a utility bin. Nothing here imports a transport, a
// storage engine or a JOSE library, and nothing here knows which context is
// using it — that is what makes it safe for a domain package to depend on.
package common

import (
	"strings"
)

// DidBuilder is the recipe for minting a DID
type DidBuilder interface {
	// Method reports which DID method this builder mints under.
	Method() DidMethod
	// Validate reports whether the parameters are usable.
	Validate() error
	// Binding clause to the interface
	isDidBuilder()
}

// JwkDidBuilder mints did:jwk, where the key itself encodes the identifier.
type JwkDidBuilder struct {
	// Pem is the key material the identifier is derived from.
	Pem string
}

// WebDidBuilder mints did:web, resolved over HTTPS from a domain.
type WebDidBuilder struct {
	Domain string
	Port   *string
	Path   *string
}

// Binding clauses
func (JwkDidBuilder) isDidBuilder() {}
func (WebDidBuilder) isDidBuilder() {}

// Method implements DidBuilder.
func (JwkDidBuilder) Method() DidMethod { return MethodJwk }

// Method implements DidBuilder.
func (WebDidBuilder) Method() DidMethod { return MethodWeb }

// Validate implements DidBuilder.
func (b JwkDidBuilder) Validate() error {
	if strings.TrimSpace(b.Pem) == "" {
		return Invalid("pem", "is required to mint a did:jwk")
	}

	return nil
}

// Validate implements DidBuilder.
func (b WebDidBuilder) Validate() error {
	if strings.TrimSpace(b.Domain) == "" {
		return Invalid("domain", "is required to mint a did:web")
	}

	// A did:web domain is an authority, not a URL: the scheme and the port live
	// elsewhere in the identifier, and a slash would be read as a path segment.
	if strings.ContainsAny(b.Domain, "/:") {
		return Invalid("domain", "must be a bare host, without scheme, port or path")
	}

	if b.Port != nil && strings.TrimSpace(*b.Port) == "" {
		return Invalid("port", "is present but empty; omit it instead")
	}

	if b.Path != nil && strings.TrimSpace(*b.Path) == "" {
		return Invalid("path", "is present but empty; omit it instead")
	}

	return nil
}

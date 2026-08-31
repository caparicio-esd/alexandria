// Package wallet holds the wallet domain: entities, business rules and the
// ports through which it reaches the outside world. It imports no transport,
// no persistence and no framework — see internal/ssi-auth for the layering.
package wallet

import (
	"fmt"
	"strings"
	"time"

	"github.com/trustbloc/did-go/doc/did"
)

// Method is the DID method a wallet identifier was minted under.
type Method string

const (
	// MethodJwk is did:jwk, where the key itself encodes the identifier.
	MethodJwk Method = "jwk"
	// MethodWeb is did:web, resolved over HTTPS from a domain.
	MethodWeb Method = "web"
)

// ParseMethod maps an external spelling onto a supported method. Peers are
// inconsistent about casing, so the comparison is case-insensitive.
func ParseMethod(s string) (Method, error) {
	switch Method(strings.ToLower(strings.TrimSpace(s))) {
	case MethodJwk:
		return MethodJwk, nil
	case MethodWeb:
		return MethodWeb, nil
	default:
		return "", fmt.Errorf("did method %q: %w", s, ErrUnsupported)
	}
}

// KeyBinding ties a stored key to the verification method fragment it is
// published under in the DID Document.
//
// KeyID is opaque to the domain: only the KeyStore that issued it knows how to
// resolve it back to key material.
type KeyBinding struct {
	KeyID    string
	Fragment string
}

// Did is a decentralised identifier held by the wallet, together with the
// document that makes it resolvable and the keys bound into it.
//
// A Did is immutable once built. Copying the struct shares the slices inside
// it, so the wallet service can hand the cached identity to concurrent callers
// without deep-copying: build a new Did rather than writing into one you were
// handed.
type Did struct {
	// ID is the identifier itself, e.g. "did:web:alexandria.upm.es".
	ID string
	// Method is how the identifier was minted.
	Method Method
	// Alias is the human-readable tag the wallet indexes it under.
	Alias string
	// Default reports whether this is the wallet active identity.
	Default bool
	// Document is the resolvable W3C DID Document. The type comes straight from
	// the standard library for DIDs: it is a specification structure, not a
	// vendor one, so there is nothing to wrap.
	Document did.Doc
	// Keys lists every key bound into the document verification methods.
	Keys []KeyBinding
	// DefaultKey is the binding used for signing unless told otherwise.
	DefaultKey KeyBinding
}

// Key is a keypair registered in the wallet.
//
// It carries no private material on purpose: the PEM lives in the KeyStore and
// never crosses back into the domain, so no use case can leak it by accident.
type Key struct {
	ID    string
	Alias string
	// Kty and Crv are the JWA spellings of the key type and curve — "OKP" and
	// "Ed25519", say. They are plain strings here on purpose: they arrive
	// already checked against the JWA registry by internal/ssi-auth/jose, and
	// naming their types would drag the JOSE library into the domain.
	Kty       string
	Crv       *string
	CreatedAt time.Time
}

// KeyPlan is a key registration as the domain states it: the storage path the
// wallet should file the material under, the alias it is indexed by, and the
// PEM itself. It travels outwards only — nothing hands one back.
type KeyPlan struct {
	ID    string
	Alias string
	Pem   string
}

// Credential is a Verifiable Credential stored in the wallet.
//
// TODO: fields are settled as the OID4VCI flow lands.
type Credential struct {
	ID        string
	Issuer    string
	Types     []string
	IssuedAt  time.Time
	ExpiresAt *time.Time
}

// Info reports the wallet runtime state.
type Info struct {
	Linked     bool
	DefaultDid string
	Keys       int
	Dids       int
	Credential int
}

// OidcURI is an inbound OID4VCI offer or OID4VP request URI.
type OidcURI struct {
	URI string
}

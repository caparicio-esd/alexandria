package wallet

import (
	"time"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/trustbloc/did-go/doc/did"
)

// ==== DID TYPES ============================================================

// Did is a decentralised identifier held by the wallet, together with the
// document that makes it resolvable and the keys bound into it.
type Did struct {
	// ID is the identifier itself, e.g. "did:web:alexandria.upm.es".
	ID string
	// Method is how the identifier was minted.
	Method common.DidMethod
	// Alias is the human-readable tag the wallet indexes it under.
	Alias string
	// Default reports whether this is the wallet active identity.
	Default bool
	// Document is the resolvable W3C DID Document
	Document did.Doc
	// Keys lists every key bound into the document verification methods.
	Keys []KeyBinding
	// DefaultKey is the binding used for signing unless told otherwise.
	DefaultKey KeyBinding
}

// KeyBinding ties a stored key to the verification method fragment it is
// published under in the DID Document.
type KeyBinding struct {
	KeyID    string
	Fragment string
}

// DidPlan is a DID registration as the domain states it: what to mint the
// identifier from, the alias to index it under, which stored keys to bind into
// the document, and what services it should publish.
//
// Like KeyPlan it travels outwards only. The wallet mints the identifier, so
// nothing in here names one.
type DidPlan struct {
	Alias   string
	Builder common.DidBuilder
	Keys    []string
	Service *[]common.DidService
}

// ==== KEY TYPES ============================================================

// Key is a keypair registered in the wallet.
type Key struct {
	ID        string
	Alias     string
	Kty       string
	Crv       *string
	CreatedAt time.Time
}

// PemDescriptor is what the domain needs to know about a piece of key material
// before it will accept it: who the key is, what kind it is, and whether it can
// sign. It is derived from the PEM, never supplied by the caller.
type PemDescriptor struct {
	// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url without
	// padding. It is the canonical name of the key: two encodings of the same
	// keypair produce the same value, and it is what a "kid" is set to.
	Thumbprint string
	// Kty is the key type — "OKP", "EC", "RSA".
	Kty string
	// Crv is the curve, absent on key types that are not on one.
	Crv *string
	// Private reports whether the material carries the private half. A public
	// key parses perfectly well and cannot sign anything.
	Private bool
}

// KeyPlan is a key registration as the domain states it: the storage path the
// wallet should file the material under, the alias it is indexed by, and the
// PEM itself. It travels outwards only — nothing hands one back.
type KeyPlan struct {
	ID    string
	Alias string
	Pem   string
}

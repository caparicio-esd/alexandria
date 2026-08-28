// Package wallet holds the wallet domain: entities, business rules and the
// ports through which it reaches the outside world. It imports no transport,
// no persistence and no framework — see internal/ssi-auth for the layering.
package wallet

import (
	"time"

	"github.com/caparicio-esd/alexandria/internal/common"
)

// Key is a keypair registered in the wallet.
//
// It carries no private material on purpose: the PEM lives in the KeyStore and
// never crosses back into the domain, so no use case can leak it by accident.
type Key struct {
	ID         string
	Alias      string
	Alg        common.Alg
	Thumbprint string
	CreatedAt  time.Time
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

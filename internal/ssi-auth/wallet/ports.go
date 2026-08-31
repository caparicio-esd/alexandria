// Package wallet is the domain of this bounded context: the use cases that hold
// key material and decentralised identifiers, and the ports through which they
// reach anything outside themselves.
//
// Nothing here imports a transport, a JOSE library or an HTTP client. The types
// the ports speak are the ones declared in this package, which is what lets the
// adapters be replaced without the rules moving.
package wallet

import (
	"context"
	"time"
)

// ===== Wallet driven adaprter port ===========================================

// Wallet is the outsourced wallet holding the key material and the DIDs.
type Wallet interface {
	// Link refreshes the wallet identity, returning whatever the default DID
	Link(ctx context.Context) (Did, error)
	// RegisterKey files raw key material under the path the plan names.
	RegisterKey(ctx context.Context, keyPlan *KeyPlan) error
	// Registers did
	RegisterDid(ctx context.Context, didPlan *DidPlan) error
}

// ===== Pem Descriptor ===========================================

// PemInspector is the port that reads key material. It exists so the domain can
// state what a registrable key is without importing a JOSE library to find out.
type PemInspector interface {
	// Inspect derives a descriptor from PEM-encoded material, reporting an
	// error whose message is safe to hand back to the caller.
	Inspect(pem string) (PemDescriptor, error)
}

// Clock is injected so credential expiry and DID timestamps stay deterministic
// under test.
type Clock interface {
	Now() time.Time
}

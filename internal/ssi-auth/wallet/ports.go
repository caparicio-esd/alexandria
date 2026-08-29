package wallet

import (
	"context"
	"time"
)

// Wallet is the outsourced wallet holding the key material and the DIDs.
//
// Everything it returns is stated in this package's own types, so the domain
// never learns which product is behind it or how it spells things on the wire.
type Wallet interface {
	// Link refreshes the wallet identity, returning whatever the remote
	// currently considers its default DID.
	Link(ctx context.Context) (Did, error)
}

// Clock is injected so credential expiry and DID timestamps stay deterministic
// under test.
type Clock interface {
	Now() time.Time
}

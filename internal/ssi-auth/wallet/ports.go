package wallet

import (
	"context"
	"time"
)

// DidRepository persists the DIDs owned by the wallet.
type DidRepository interface {
	Save(ctx context.Context, did Did) error
	ByID(ctx context.Context, id string) (Did, error)
	Default(ctx context.Context) (Did, error)
	List(ctx context.Context) ([]Did, error)
	Delete(ctx context.Context, id string) error
}

// KeyStore holds the private key material backing the wallet DIDs.
type KeyStore interface {
	Store(ctx context.Context, pem string, alias *string) (Key, error)
	ByID(ctx context.Context, id string) (Key, error)
	List(ctx context.Context) ([]Key, error)
	Delete(ctx context.Context, id string) error
}

// CredentialRepository persists the Verifiable Credentials held by the wallet.
type CredentialRepository interface {
	List(ctx context.Context) ([]Credential, error)
	Delete(ctx context.Context, id string) error
}

// Directory is the external ecosystem registry the wallet links itself against.
type Directory interface {
	Link(ctx context.Context, did string) error
	IsLinked(ctx context.Context, did string) (bool, error)
}

// Clock is injected so credential expiry and DID timestamps stay deterministic
// under test.
type Clock interface {
	Now() time.Time
}

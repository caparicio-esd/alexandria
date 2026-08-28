package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/caparicio-esd/alexandria/internal/did"
)

// Service holds the wallet use cases. It is the centre of the hexagon: every
// dependency is a secondary port declared in this package, so the business
// rules stay free of transport and persistence concerns. Driving adapters, such
// as the REST router, consume this type directly.
type Service struct {
	dids        DidRepository
	keys        KeyStore
	credentials CredentialRepository
	directory   Directory
	clock       Clock
}

// NewService wires the wallet use cases to their outbound dependencies. The
// constructor is the only door: the fields stay unexported so no adapter can
// swap a dependency after construction.
func NewService(
	dids DidRepository,
	keys KeyStore,
	credentials CredentialRepository,
	directory Directory,
	clock Clock,
) *Service {
	return &Service{
		dids:        dids,
		keys:        keys,
		credentials: credentials,
		directory:   directory,
		clock:       clock,
	}
}

// ===== Linking ===============================================================

// Link registers the wallet against the external ecosystem directory.
func (s *Service) Link(ctx context.Context) error {
	panic("wallet: Link not implemented")
}

// IsLinked reports whether the wallet is registered in the directory.
func (s *Service) IsLinked(ctx context.Context) bool {
	panic("wallet: IsLinked not implemented")
}

// ===== Keys ==================================================================

// RegisterKey imports raw PEM key material and indexes it under an optional alias.
func (s *Service) RegisterKey(ctx context.Context, pem string, alias *string) error {
	panic("wallet: RegisterKey not implemented")
}

// DeleteKey purges a key, provided no DID still references it.
func (s *Service) DeleteKey(ctx context.Context, id string) error {
	panic("wallet: DeleteKey not implemented")
}

// Keys lists every keypair held by the wallet.
func (s *Service) Keys(ctx context.Context) ([]Key, error) {
	panic("wallet: Keys not implemented")
}

// ===== DIDs ==================================================================

// RegisterDid mints a local DID from the given builder, binding the referenced
// keys as verification methods, and persists it.
//
// The minting rules live in DidBuilder.Build; this method only orchestrates the
// secondary ports around them.
func (s *Service) RegisterDid(
	ctx context.Context,
	builder DidBuilder,
	keysID []string,
	alias *string,
	service []did.Service,
) (Did, error) {
	keys, err := s.resolveKeys(ctx, keysID)
	if err != nil {
		return Did{}, err
	}

	// The variable is not named did: that is the shared kernel package.
	minted, err := builder.Build(keys, service, s.clock.Now(), derefOr(alias, ""))
	if err != nil {
		return Did{}, err
	}

	id := minted.ID.String()

	if _, err := s.dids.ByID(ctx, id); err == nil {
		return Did{}, fmt.Errorf("%w: did %s already registered", ErrConflict, id)
	} else if !errors.Is(err, ErrNotFound) {
		return Did{}, fmt.Errorf("checking for an existing did: %w", err)
	}

	if err := s.dids.Save(ctx, minted); err != nil {
		return Did{}, fmt.Errorf("saving did %s: %w", id, err)
	}

	return minted, nil
}

// resolveKeys loads every referenced key, rejecting unknown and duplicated ids.
func (s *Service) resolveKeys(ctx context.Context, keysID []string) ([]Key, error) {
	seen := make(map[string]struct{}, len(keysID))
	keys := make([]Key, 0, len(keysID))

	for i, id := range keysID {
		if _, dup := seen[id]; dup {
			return nil, invalid(fmt.Sprintf("keys_id[%d]", i), "duplicated key id "+id)
		}
		seen[id] = struct{}{}

		k, err := s.keys.ByID(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: key %s", ErrNotFound, id)
			}

			return nil, fmt.Errorf("loading key %s: %w", id, err)
		}

		keys = append(keys, k)
	}

	return keys, nil
}

// derefOr returns the pointed-to value, or fallback when the pointer is nil.
func derefOr[T any](p *T, fallback T) T {
	if p == nil {
		return fallback
	}

	return *p
}

// Did resolves the identifier of the wallet default DID.
func (s *Service) Did(ctx context.Context) (string, error) {
	panic("wallet: Did not implemented")
}

// DidDoc resolves the DID Document of the default DID, as served publicly.
func (s *Service) DidDoc(ctx context.Context) (did.Document, error) {
	panic("wallet: DidDoc not implemented")
}

// DeleteDid drops a DID and its verification method bindings.
func (s *Service) DeleteDid(ctx context.Context, id string) error {
	panic("wallet: DeleteDid not implemented")
}

// SetDefaultDid promotes a DID to be the wallet primary identity.
func (s *Service) SetDefaultDid(ctx context.Context, id string) (Did, error) {
	panic("wallet: SetDefaultDid not implemented")
}

// ===== DID verification methods ==============================================

// AddKeyToDid binds a key into the verification methods of a DID.
func (s *Service) AddKeyToDid(ctx context.Context, didID, keyID string) (Did, error) {
	panic("wallet: AddKeyToDid not implemented")
}

// RemoveKeyFromDid unbinds a key from the verification methods of a DID.
func (s *Service) RemoveKeyFromDid(ctx context.Context, didID, keyID string) (Did, error) {
	panic("wallet: RemoveKeyFromDid not implemented")
}

// SetDefaultKey promotes a key to be the default verification method of a DID.
func (s *Service) SetDefaultKey(ctx context.Context, didID, keyID string) (Did, error) {
	panic("wallet: SetDefaultKey not implemented")
}

// ===== Credentials ===========================================================

// DeleteCredential purges a stored Verifiable Credential.
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	panic("wallet: DeleteCredential not implemented")
}

// Credentials lists every Verifiable Credential held by the wallet.
func (s *Service) Credentials(ctx context.Context) ([]Credential, error) {
	panic("wallet: Credentials not implemented")
}

// ===== Runtime state =========================================================

// Info reports the wallet runtime state.
func (s *Service) Info(ctx context.Context) (Info, error) {
	panic("wallet: Info not implemented")
}

// ===== OpenID4VC =============================================================

// ProcessOid4vci accepts an inbound OID4VCI credential offer and stores the
// credential it yields.
func (s *Service) ProcessOid4vci(ctx context.Context, uri OidcURI) error {
	panic("wallet: ProcessOid4vci not implemented")
}

// ProcessOid4vp answers an outbound OID4VP presentation request.
func (s *Service) ProcessOid4vp(ctx context.Context, uri OidcURI) error {
	panic("wallet: ProcessOid4vp not implemented")
}

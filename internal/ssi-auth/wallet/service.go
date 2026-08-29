package wallet

import (
	"context"
	"fmt"
	"sync"

	"github.com/trustbloc/did-go/doc/did"
)

// Service holds the wallet use cases. It is the centre of the hexagon: every
// dependency is a secondary port declared in this package, so the business
// rules stay free of transport and persistence concerns. Driving adapters, such
// as the REST router, consume this type directly.
type Service struct {
	wallet   Wallet
	clock    Clock
	mu       sync.RWMutex
	identity *Did
}

// NewService wires the wallet use cases to their outbound dependencies. The
// constructor is the only door: the fields stay unexported so no adapter can
// swap a dependency after construction.
func NewService(
	wallet Wallet,
	clock Clock,
) *Service {
	return &Service{
		wallet:   wallet,
		clock:    clock,
		mu:       sync.RWMutex{},
		identity: nil,
	}
}

// ===== Linking ===============================================================

// Link refreshes the wallet identity from the outsourced wallet.
func (s *Service) Link(ctx context.Context) (Did, error) {
	did, err := s.wallet.Link(ctx)
	if err != nil {
		return Did{}, fmt.Errorf("linking wallet: %w", err)
	}

	if did.ID == "" {
		return Did{}, fmt.Errorf("wallet reported no default did: %w", ErrNotLinked)
	}
	s.setIdentity(did)
	return did, nil
}

// IsLinked reports whether the wallet is registered in the directory.
func (s *Service) IsLinked(ctx context.Context) bool {
	_, ok := s.identitySnapshot()
	return ok
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
) (string, error) {
	panic("wallet: Did not implemented")
}

// Did resolves the identifier of the wallet default DID.
func (s *Service) Did(ctx context.Context) (string, error) {
	id, ok := s.identitySnapshot()
	if !ok {
		return "", ErrNotLinked
	}
	return id.ID, nil
}

// DidDoc resolves the DID Document of the default DID, as served publicly.
func (s *Service) DidDoc(ctx context.Context) (did.Doc, error) {
	identity, ok := s.identitySnapshot()
	if !ok {
		return did.Doc{}, ErrNotLinked
	}

	return identity.Document, nil
}

// DeleteDid drops a DID and its verification method bindings.
func (s *Service) DeleteDid(ctx context.Context, id string) error {
	panic("wallet: DeleteDid not implemented")
}

// SetDefaultDid promotes a DID to be the wallet primary identity.
func (s *Service) SetDefaultDid(ctx context.Context, id string) (string, error) {
	panic("wallet: SetDefaultDid not implemented")
}

// ===== DID verification methods ==============================================

// AddKeyToDid binds a key into the verification methods of a DID.
func (s *Service) AddKeyToDid(ctx context.Context, didID, keyID string) (string, error) {
	panic("wallet: AddKeyToDid not implemented")
}

// RemoveKeyFromDid unbinds a key from the verification methods of a DID.
func (s *Service) RemoveKeyFromDid(ctx context.Context, didID, keyID string) (string, error) {
	panic("wallet: RemoveKeyFromDid not implemented")
}

// SetDefaultKey promotes a key to be the default verification method of a DID.
func (s *Service) SetDefaultKey(ctx context.Context, didID, keyID string) (string, error) {
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

// =============================================================
// Accesors
// =============================================================

// setIdentity replaces the active identity.
func (s *Service) setIdentity(d Did) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = &d
}

// adopt replaces the active identity only if the wallet promoted this DID
// to default. Mutations funnel through here.
func (s *Service) adopt(d Did) {
	if d.Default {
		s.setIdentity(d)
	}
}

// identitySnapshot returns the active identity, or false if not linked yet.
func (s *Service) identitySnapshot() (Did, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.identity == nil {
		return Did{}, false
	}
	return *s.identity, true
}

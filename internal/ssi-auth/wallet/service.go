package wallet

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/trustbloc/did-go/doc/did"
)

// Service is the wallet use case. It owns the rules — what key material is
// acceptable, what a DID needs before it can be minted — and delegates
// everything else through the ports.
//
// The active identity is cached behind a mutex because it is read on every
// request that needs to sign and written only when the wallet is relinked.
type Service struct {
	wallet       Wallet
	pemInspector PemInspector
	clock        Clock
	logger       *slog.Logger
	mu           sync.RWMutex
	identity     *Did
}

// NewService wires the use case onto its ports. A nil logger falls back to the
// default one; the ports themselves are required.
func NewService(
	wallet Wallet,
	pemInspector PemInspector,
	clock Clock,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		wallet:       wallet,
		pemInspector: pemInspector,
		clock:        clock,
		logger:       logger,
		mu:           sync.RWMutex{},
		identity:     nil,
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
		return Did{}, fmt.Errorf("wallet reported no default did: %w", common.ErrNotLinked)
	}
	s.setIdentity(did)
	s.logger.InfoContext(ctx, "identity established", "did", did.ID, "alias", did.Alias)

	return did, nil
}

// IsLinked reports whether the wallet is registered in the directory.
func (s *Service) IsLinked(_ context.Context) bool {
	_, ok := s.identitySnapshot()
	return ok
}

// ===== Keys ==================================================================

// RegisterKey imports raw PEM key material and indexes it under an optional
// alias, filed under the identifier the caller names.
//
// A nil id means the caller has no opinion, and the domain names the key after
// its RFC 7638 thumbprint: the same keypair always lands on the same value, so
// registering it twice is idempotent rather than duplicated. A caller that does
// name it takes that guarantee off the table, which is its right — it is the one
// that has to find the key again.
//
// The material is inspected before it travels: a wallet that accepts anything
// fails later, at signing time, with an error that no longer points at the
// request that caused it. What the inspection rejects is stated here rather
// than in the adapter, because "a registered key must be able to sign" is a
// rule of this domain, not a property of PEM.
func (s *Service) RegisterKey(ctx context.Context, pem string, alias *string, id *string) error {
	var a string
	if alias != nil {
		a = *alias
	}

	pemDescriptor, err := s.pemInspector.Inspect(pem)
	if err != nil {
		return common.Invalid("pem", err.Error())
	}

	if !pemDescriptor.Private {
		return common.Invalid("pem", "carries only a public key; the wallet has to be able to sign with it")
	}

	keyID := fmt.Sprintf("%s.json", pemDescriptor.Thumbprint)
	if id != nil {
		if strings.TrimSpace(*id) == "" {
			return common.Invalid("id", "is present but empty; omit it to have the key named after its thumbprint")
		}

		keyID = *id
	}

	keyPlan := &KeyPlan{
		ID:    keyID,
		Alias: a,
		Pem:   pem,
	}

	if err := s.wallet.RegisterKey(ctx, keyPlan); err != nil {
		return fmt.Errorf("wallet reported error by key registering: %w", err)
	}

	s.logger.InfoContext(ctx, "key registered",
		"id", keyID, "kid", pemDescriptor.Thumbprint,
		"kty", pemDescriptor.Kty, "alias", a)

	return nil
}

// DeleteKey purges a key, provided no DID still references it.
func (s *Service) DeleteKey(_ context.Context, _ string) error {
	panic("wallet: DeleteKey not implemented")
}

// Keys lists every keypair held by the wallet.
func (s *Service) Keys(_ context.Context) ([]Key, error) {
	panic("wallet: Keys not implemented")
}

// ===== DIDs ==================================================================

// RegisterDid mints a local DID from the given builder, binding the referenced
// keys as verification methods, and persists it.
func (s *Service) RegisterDid(
	ctx context.Context,
	builder common.DidBuilder,
	keys []string,
	alias string,
	services []common.DidService,
) error {
	if err := builder.Validate(); err != nil {
		return fmt.Errorf("wallet reported error by did registering: %w", err)
	}

	// A DID with no key bound into it resolves to a document that cannot verify
	// anything. The wallet would accept it and the failure would surface later,
	// at signing time, far from the request that caused it.
	if len(keys) == 0 {
		return common.Invalid("keys", "is required: a did needs at least one key bound into it")
	}

	for _, k := range keys {
		if strings.TrimSpace(k) == "" {
			return common.Invalid("keys", "carries an empty key id")
		}
	}

	didPlan := &DidPlan{
		Builder: builder,
		Alias:   alias,
		Keys:    keys,
		Service: &services,
	}

	err := s.wallet.RegisterDid(ctx, didPlan)
	if err != nil {
		return fmt.Errorf("wallet reported error by did registering: %w", err)
	}

	s.logger.InfoContext(ctx, "did registered",
		"method", builder.Method(), "keys", keys)

	return nil
}

// Did resolves the identifier of the wallet default DID.
func (s *Service) Did(_ context.Context) (string, error) {
	id, ok := s.identitySnapshot()
	if !ok {
		return "", common.ErrNotLinked
	}
	return id.ID, nil
}

// DidDoc resolves the DID Document of the default DID, as served publicly.
func (s *Service) DidDoc(_ context.Context) (did.Doc, error) {
	identity, ok := s.identitySnapshot()
	if !ok {
		return did.Doc{}, common.ErrNotLinked
	}

	return identity.Document, nil
}

// DeleteDid drops a DID and its verification method bindings.
func (s *Service) DeleteDid(_ context.Context, _ string) error {
	panic("wallet: DeleteDid not implemented")
}

// SetDefaultDid promotes a DID to be the wallet primary identity.
func (s *Service) SetDefaultDid(_ context.Context, _ string) (string, error) {
	panic("wallet: SetDefaultDid not implemented")
}

// ===== DID verification methods ==============================================

// AddKeyToDid binds a key into the verification methods of a DID.
func (s *Service) AddKeyToDid(_ context.Context, _, _ string) (string, error) {
	panic("wallet: AddKeyToDid not implemented")
}

// RemoveKeyFromDid unbinds a key from the verification methods of a DID.
func (s *Service) RemoveKeyFromDid(_ context.Context, _, _ string) (string, error) {
	panic("wallet: RemoveKeyFromDid not implemented")
}

// SetDefaultKey promotes a key to be the default verification method of a DID.
func (s *Service) SetDefaultKey(_ context.Context, _, _ string) (string, error) {
	panic("wallet: SetDefaultKey not implemented")
}

// ===== Credentials ===========================================================

// DeleteCredential purges a stored Verifiable Credential.
func (s *Service) DeleteCredential(_ context.Context, _ string) error {
	panic("wallet: DeleteCredential not implemented")
}

// Credentials lists every Verifiable Credential held by the wallet.
func (s *Service) Credentials(_ context.Context) error {
	panic("wallet: Credentials not implemented")
}

// ===== Runtime state =========================================================

// Info reports the wallet runtime state.
func (s *Service) Info(_ context.Context) error {
	panic("wallet: Info not implemented")
}

// ===== OpenID4VC =============================================================

// ProcessOid4vci accepts an inbound OID4VCI credential offer and stores the
// credential it yields.
func (s *Service) ProcessOid4vci(_ context.Context) error {
	panic("wallet: ProcessOid4vci not implemented")
}

// ProcessOid4vp answers an outbound OID4VP presentation request.
func (s *Service) ProcessOid4vp(_ context.Context) error {
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
//
// AddKeyToDid, RegisterDid once it returns the minted DID — are the ones still
// unimplemented below. It states the invariant they have to keep.
//
//nolint:unused // the mutations that funnel through it — SetDefaultDid,
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

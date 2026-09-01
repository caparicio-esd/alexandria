package wallet_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

const testPem = "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----\n"

// stubWallet stands in for the outsourced wallet. It records the plan it was
// handed, which is the whole point: RegisterKey's job is minting that plan.
type stubWallet struct {
	gotPlan       *wallet.KeyPlan
	gotDidPlan    *wallet.DidPlan
	gotDeleteKey  *string
	gotDeleteDid  *string
	gotDefaultDid *string
	gotDidByID    *string
	gotBinding    *binding
	keys          []wallet.Key
	dids          []wallet.Did
	did           wallet.Did
	err           error
}

func (s *stubWallet) Link(context.Context) (wallet.Did, error) {
	return wallet.Did{}, errors.New("not used in this test")
}

func (s *stubWallet) RegisterKey(_ context.Context, plan *wallet.KeyPlan) error {
	s.gotPlan = plan

	return s.err
}

func (s *stubWallet) GetAllKeys(context.Context) ([]wallet.Key, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.keys, nil
}

func (s *stubWallet) DeleteKey(_ context.Context, keyID string) error {
	s.gotDeleteKey = &keyID

	return s.err
}

func (s *stubWallet) DeleteDid(_ context.Context, didID string) error {
	s.gotDeleteDid = &didID

	return s.err
}

func (s *stubWallet) RegisterDid(_ context.Context, plan *wallet.DidPlan) error {
	s.gotDidPlan = plan

	return s.err
}

func (s *stubWallet) GetAllDids(context.Context) ([]wallet.Did, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.dids, nil
}

func (s *stubWallet) GetDidByID(_ context.Context, didID string) (wallet.Did, error) {
	s.gotDidByID = &didID

	if s.err != nil {
		return wallet.Did{}, s.err
	}

	return s.did, nil
}

func (s *stubWallet) SetDefaultDid(_ context.Context, didID string) error {
	s.gotDefaultDid = &didID

	return s.err
}

func (s *stubWallet) AddKeyToDid(_ context.Context, didID, keyID string) error {
	s.gotBinding = &binding{op: "add", did: didID, key: keyID}

	return s.err
}

func (s *stubWallet) RemoveKeyFromDid(_ context.Context, didID, keyID string) error {
	s.gotBinding = &binding{op: "remove", did: didID, key: keyID}

	return s.err
}

func (s *stubWallet) SetDefaultKey(_ context.Context, didID, keyID string) error {
	s.gotBinding = &binding{op: "default", did: didID, key: keyID}

	return s.err
}

// binding records which verification-method mutation the port saw, and with
// which pair of identifiers: the two are interchangeable in type and not in
// meaning, so a swapped argument is exactly the mistake worth pinning.
type binding struct {
	op  string
	did string
	key string
}

// stubKeys stands in for the PEM inspector. The use case is not being tested on
// its ability to parse a key — that is the adapter's job, tested next to it —
// but on what it does with the verdict, so the verdict is dictated here.
type stubKeys struct {
	gotPem     string
	descriptor wallet.PemDescriptor
	err        error
}

func (s *stubKeys) Inspect(pem string) (wallet.PemDescriptor, error) {
	s.gotPem = pem

	return s.descriptor, s.err
}

// usableKey is the verdict for material the wallet should accept.
func usableKey(thumbprint string) *stubKeys {
	return &stubKeys{
		descriptor: wallet.PemDescriptor{
			Thumbprint: thumbprint,
			Kty:        "OKP",
			Crv:        nil,
			Private:    true,
		},
	}
}

// TestRegisterKeyMintsAPlan pins what the use case adds over the port: a storage
// path named after the key, and the PEM passed through untouched.
func TestRegisterKeyMintsAPlan(t *testing.T) {
	t.Parallel()

	const thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	alias := "signing"
	stub := &stubWallet{}
	inspector := usableKey(thumbprint)
	svc := wallet.NewService(stub, inspector, nil, nil)

	if err := svc.RegisterKey(t.Context(), testPem, &alias, nil); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	if inspector.gotPem != testPem {
		t.Errorf("the inspector saw %q, want the pem the caller sent", inspector.gotPem)
	}

	if stub.gotPlan == nil {
		t.Fatal("the wallet was never called")
	}

	if stub.gotPlan.Pem != testPem {
		t.Errorf("plan.Pem = %q, want the pem it was handed", stub.gotPlan.Pem)
	}

	if stub.gotPlan.Alias != alias {
		t.Errorf("plan.Alias = %q, want %q", stub.gotPlan.Alias, alias)
	}

	// The id is the path the wallet writes the material to, and it has to be
	// flat: Fafnir's development vault does not create parent directories.
	id, ok := strings.CutSuffix(stub.gotPlan.ID, ".json")
	if !ok {
		t.Fatalf("plan.ID = %q, want a .json name", stub.gotPlan.ID)
	}

	if strings.ContainsAny(id, "/+=") {
		t.Errorf("plan.ID = %q, want a flat base64url name: a nested path fails the vault write", stub.gotPlan.ID)
	}

	if id != thumbprint {
		t.Errorf("plan.ID = %q, want the key thumbprint %q", stub.gotPlan.ID, thumbprint)
	}
}

// TestRegisterKeyIsIdempotentInItsID is the point of naming the key after its
// own thumbprint: the same material registered twice claims the same path, so
// the wallet can recognise the repeat instead of storing a second copy.
func TestRegisterKeyIsIdempotentInItsID(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}
	svc := wallet.NewService(stub, usableKey("same-key"), nil, nil)

	if err := svc.RegisterKey(t.Context(), testPem, nil, nil); err != nil {
		t.Fatalf("first RegisterKey: %v", err)
	}

	first := stub.gotPlan.ID

	if err := svc.RegisterKey(t.Context(), testPem, nil, nil); err != nil {
		t.Fatalf("second RegisterKey: %v", err)
	}

	if stub.gotPlan.ID != first {
		t.Errorf("the same key was filed as %q and then %q", first, stub.gotPlan.ID)
	}
}

// TestRegisterKeyDistinguishesKeys is the other half of that: two keys must not
// collide, or one would overwrite the other in the vault.
func TestRegisterKeyDistinguishesKeys(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}

	svc := wallet.NewService(stub, usableKey("first-key"), nil, nil)
	if err := svc.RegisterKey(t.Context(), testPem, nil, nil); err != nil {
		t.Fatalf("first RegisterKey: %v", err)
	}

	first := stub.gotPlan.ID

	svc = wallet.NewService(stub, usableKey("second-key"), nil, nil)
	if err := svc.RegisterKey(t.Context(), testPem, nil, nil); err != nil {
		t.Fatalf("second RegisterKey: %v", err)
	}

	if stub.gotPlan.ID == first {
		t.Errorf("both keys were filed as %q", first)
	}
}

// TestRegisterKeyRejectsUnreadableMaterial keeps the inspector's verdict in
// front of the wallet: bad material must not reach the vault at all.
func TestRegisterKeyRejectsUnreadableMaterial(t *testing.T) {
	t.Parallel()

	const reason = "is not readable pem key material"

	stub := &stubWallet{}
	svc := wallet.NewService(stub, &stubKeys{err: errors.New(reason)}, nil, nil)

	err := svc.RegisterKey(t.Context(), "not a pem", nil, nil)
	if !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("error = %v, want it to match %v", err, common.ErrInvalidInput)
	}

	// The adapter's message is what tells the caller which part of their
	// request was wrong, so it has to survive to the response.
	var invalid common.ValidationError
	if errors.As(err, &invalid) {
		if invalid.Field != "pem" {
			t.Errorf("field = %q, want %q", invalid.Field, "pem")
		}

		if invalid.Reason != reason {
			t.Errorf("reason = %q, want the inspector's own %q", invalid.Reason, reason)
		}
	}

	if stub.gotPlan != nil {
		t.Error("the wallet was asked to store material the inspector rejected")
	}
}

// TestRegisterKeyRejectsAPublicKey pins the rule that belongs to the domain
// rather than to the parser: a public key is perfectly well-formed and cannot
// sign, which is the only reason this wallet holds keys.
func TestRegisterKeyRejectsAPublicKey(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}
	inspector := usableKey("public-only")
	inspector.descriptor.Private = false

	svc := wallet.NewService(stub, inspector, nil, nil)

	err := svc.RegisterKey(t.Context(), testPem, nil, nil)
	if !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("error = %v, want it to match %v", err, common.ErrInvalidInput)
	}

	if stub.gotPlan != nil {
		t.Error("a public key reached the vault")
	}
}

// TestRegisterKeyWithoutAlias pins the nil alias: the wallet requires the field,
// so it goes out empty rather than absent.
func TestRegisterKeyWithoutAlias(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}
	svc := wallet.NewService(stub, usableKey("no-alias"), nil, nil)

	if err := svc.RegisterKey(t.Context(), testPem, nil, nil); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	if stub.gotPlan.Alias != "" {
		t.Errorf("plan.Alias = %q, want empty", stub.gotPlan.Alias)
	}
}

// TestRegisterKeyWrapsWalletErrors keeps the sentinel reachable through the use
// case, so the REST layer still renders a 409 rather than a 500.
func TestRegisterKeyWrapsWalletErrors(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{err: common.ErrConflict}
	svc := wallet.NewService(stub, usableKey("conflicting"), nil, nil)

	err := svc.RegisterKey(t.Context(), testPem, nil, nil)
	if !errors.Is(err, common.ErrConflict) {
		t.Errorf("error = %v, want it to match %v", err, common.ErrConflict)
	}
}

// ===== Keys listing ==========================================================

// TestKeysPassesTheWalletInventoryThrough pins that listing is a pass-through:
// the use case adds no rules of its own, so whatever the wallet holds is what
// the caller sees, in the order the wallet stated it.
func TestKeysPassesTheWalletInventoryThrough(t *testing.T) {
	t.Parallel()

	crv := "Ed25519"
	stub := &stubWallet{keys: []wallet.Key{
		{ID: "first.json", Alias: "signing", Kty: "OKP", Crv: &crv},
		{ID: "second.json", Alias: "", Kty: "RSA", Crv: nil},
	}}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	keys, err := svc.Keys(t.Context())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	if len(keys) != len(stub.keys) {
		t.Fatalf("got %d keys, want %d", len(keys), len(stub.keys))
	}

	for i, want := range stub.keys {
		if keys[i].ID != want.ID || keys[i].Alias != want.Alias || keys[i].Kty != want.Kty {
			t.Errorf("keys[%d] = %+v, want %+v", i, keys[i], want)
		}
	}
}

// TestKeysOnAnEmptyWallet keeps "no keys" from reading as a failure: an empty
// vault is a legitimate state, and the REST layer renders it as an empty array.
func TestKeysOnAnEmptyWallet(t *testing.T) {
	t.Parallel()

	svc := wallet.NewService(&stubWallet{}, usableKey("unused"), nil, nil)

	keys, err := svc.Keys(t.Context())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("got %d keys, want none", len(keys))
	}
}

// TestKeysWrapsWalletErrors keeps the sentinel reachable, so an unreachable
// wallet is not reported as an empty one.
func TestKeysWrapsWalletErrors(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{err: common.ErrNotFound}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	keys, err := svc.Keys(t.Context())
	if !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("error = %v, want it to match %v", err, common.ErrNotFound)
	}

	if len(keys) != 0 {
		t.Errorf("got %d keys alongside an error, want none", len(keys))
	}
}

// ===== Key deletion ==========================================================

// TestDeleteKeyReachesTheWallet pins the identifier the use case forwards: the
// wallet files material under that exact path, so a rewritten id deletes either
// nothing or the wrong key.
func TestDeleteKeyReachesTheWallet(t *testing.T) {
	t.Parallel()

	const keyID = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs.json"

	stub := &stubWallet{}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	if err := svc.DeleteKey(t.Context(), keyID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	if stub.gotDeleteKey == nil {
		t.Fatal("the wallet was never called")
	}

	if *stub.gotDeleteKey != keyID {
		t.Errorf("deleted %q, want %q", *stub.gotDeleteKey, keyID)
	}

	if stub.gotDeleteDid != nil {
		t.Error("deleting a key reached the did endpoint")
	}
}

// TestDeleteKeyWrapsWalletErrors keeps the sentinel reachable, so deleting a key
// that is not there still renders a 404 rather than a 500.
func TestDeleteKeyWrapsWalletErrors(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{err: common.ErrNotFound}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	err := svc.DeleteKey(t.Context(), "missing.json")
	if !errors.Is(err, common.ErrNotFound) {
		t.Errorf("error = %v, want it to match %v", err, common.ErrNotFound)
	}
}

// ===== DID deletion ==========================================================

// TestDeleteDidReachesTheDidEndpoint is the reason this test exists: keys and
// DIDs are two different collections in the wallet, and forwarding a DID to the
// key endpoint silently deletes nothing while reporting success.
func TestDeleteDidReachesTheDidEndpoint(t *testing.T) {
	t.Parallel()

	const didID = "did:web:alexandria.upm.es"

	stub := &stubWallet{}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	if err := svc.DeleteDid(t.Context(), didID); err != nil {
		t.Fatalf("DeleteDid: %v", err)
	}

	if stub.gotDeleteKey != nil {
		t.Errorf("deleting a did deleted the key %q instead", *stub.gotDeleteKey)
	}

	if stub.gotDeleteDid == nil {
		t.Fatal("the wallet was never called")
	}

	if *stub.gotDeleteDid != didID {
		t.Errorf("deleted %q, want %q", *stub.gotDeleteDid, didID)
	}
}

// TestDeleteDidWrapsWalletErrors keeps the sentinel reachable through the use
// case.
func TestDeleteDidWrapsWalletErrors(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{err: common.ErrConflict}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	err := svc.DeleteDid(t.Context(), "did:web:alexandria.upm.es")
	if !errors.Is(err, common.ErrConflict) {
		t.Errorf("error = %v, want it to match %v", err, common.ErrConflict)
	}
}

// ===== DID listing ===========================================================

// TestGetAllDidsPassesTheWalletInventoryThrough pins that listing DIDs is a
// pass-through, in the order the wallet stated them.
func TestGetAllDidsPassesTheWalletInventoryThrough(t *testing.T) {
	t.Parallel()

	held := []wallet.Did{
		{ID: "475e5c94", Alias: "base", Default: true},
		{ID: "9b2f0a13", Alias: "spare"},
	}

	stub := &stubWallet{dids: held}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	dids, err := svc.GetAllDids(t.Context())
	if err != nil {
		t.Fatalf("GetAllDids: %v", err)
	}

	if len(dids) != len(held) {
		t.Fatalf("got %d dids, want %d", len(dids), len(held))
	}

	for i, want := range held {
		if dids[i].ID != want.ID || dids[i].Alias != want.Alias || dids[i].Default != want.Default {
			t.Errorf("dids[%d] = %+v, want %+v", i, dids[i], want)
		}
	}
}

// TestGetAllDidsOnAnEmptyWallet keeps "no dids" from reading as a failure: a
// wallet that holds none is a legitimate state.
func TestGetAllDidsOnAnEmptyWallet(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	dids, err := svc.GetAllDids(t.Context())
	if err != nil {
		t.Fatalf("GetAllDids: %v", err)
	}

	if len(dids) != 0 {
		t.Errorf("got %d dids, want none", len(dids))
	}
}

// TestGetAllDidsWrapsWalletErrors keeps the sentinel reachable, so an
// unreachable wallet is not reported as one holding no dids.
func TestGetAllDidsWrapsWalletErrors(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{err: common.ErrNotFound}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	dids, err := svc.GetAllDids(t.Context())
	if !errors.Is(err, common.ErrNotFound) {
		t.Errorf("error = %v, want it to match %v", err, common.ErrNotFound)
	}

	if len(dids) != 0 {
		t.Errorf("got %d dids alongside an error, want none", len(dids))
	}
}

// ===== DID resolution ========================================================

// TestGetDidByIDForwardsTheIdentifier pins the identifier the use case hands
// on: a rewritten one resolves either nothing or the wrong record.
func TestGetDidByIDForwardsTheIdentifier(t *testing.T) {
	t.Parallel()

	const didID = "475e5c94-5bb5-4ce1-8820-9e39dc992213"

	stub := &stubWallet{did: wallet.Did{ID: didID, Alias: "base"}}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	got, err := svc.GetDidByID(t.Context(), didID)
	if err != nil {
		t.Fatalf("GetDidByID: %v", err)
	}

	if stub.gotDidByID == nil {
		t.Fatal("the wallet was never called")
	}

	if *stub.gotDidByID != didID {
		t.Errorf("resolved %q, want %q", *stub.gotDidByID, didID)
	}

	if got.ID != didID || got.Alias != "base" {
		t.Errorf("did = %+v, want the record the wallet held", got)
	}
}

// TestGetDidByIDWrapsWalletErrors keeps the sentinel reachable, so a did that is
// not there still renders a 404 rather than a 500.
func TestGetDidByIDWrapsWalletErrors(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{err: common.ErrNotFound}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	if _, err := svc.GetDidByID(t.Context(), "missing"); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("error = %v, want it to match %v", err, common.ErrNotFound)
	}
}

// ===== DID and key promotion =================================================

// TestSetDefaultDidForwardsTheIdentifier pins the identifier promoted, since
// promoting the wrong one silently changes what the wallet signs with.
func TestSetDefaultDidForwardsTheIdentifier(t *testing.T) {
	t.Parallel()

	const didID = "did:web:alexandria.upm.es"

	stub := &stubWallet{}
	svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

	if err := svc.SetDefaultDid(t.Context(), didID); err != nil {
		t.Fatalf("SetDefaultDid: %v", err)
	}

	if stub.gotDefaultDid == nil {
		t.Fatal("the wallet was never called")
	}

	if *stub.gotDefaultDid != didID {
		t.Errorf("promoted %q, want %q", *stub.gotDefaultDid, didID)
	}
}

// TestKeyBindingsForwardBothIdentifiers pins that the DID and the key reach the
// port in that order, on each of the three mutations that take both.
func TestKeyBindingsForwardBothIdentifiers(t *testing.T) {
	t.Parallel()

	const (
		didID = "did:web:alexandria.upm.es"
		keyID = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs.json"
	)

	calls := map[string]func(*wallet.Service) error{
		"add":     func(s *wallet.Service) error { return s.AddKeyToDid(t.Context(), didID, keyID) },
		"remove":  func(s *wallet.Service) error { return s.RemoveKeyFromDid(t.Context(), didID, keyID) },
		"default": func(s *wallet.Service) error { return s.SetDefaultKey(t.Context(), didID, keyID) },
	}

	for op, call := range calls {
		t.Run(op, func(t *testing.T) {
			t.Parallel()

			stub := &stubWallet{}
			svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

			if err := call(svc); err != nil {
				t.Fatalf("%s: %v", op, err)
			}

			if stub.gotBinding == nil {
				t.Fatal("the wallet was never called")
			}

			want := binding{op: op, did: didID, key: keyID}
			if *stub.gotBinding != want {
				t.Errorf("binding = %+v, want %+v", *stub.gotBinding, want)
			}
		})
	}
}

// TestDidMutationsWrapWalletErrors is the regression these mutations earned:
// each of them built its error and dropped it, so a wallet that answered 404
// was reported to the caller as a success.
func TestDidMutationsWrapWalletErrors(t *testing.T) {
	t.Parallel()

	calls := map[string]func(*wallet.Service) error{
		"set default did": func(s *wallet.Service) error {
			return s.SetDefaultDid(t.Context(), "did:web:missing")
		},
		"add key to did": func(s *wallet.Service) error {
			return s.AddKeyToDid(t.Context(), "did:web:missing", "missing.json")
		},
		"remove key from did": func(s *wallet.Service) error {
			return s.RemoveKeyFromDid(t.Context(), "did:web:missing", "missing.json")
		},
		"set default key": func(s *wallet.Service) error {
			return s.SetDefaultKey(t.Context(), "did:web:missing", "missing.json")
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			stub := &stubWallet{err: common.ErrNotFound}
			svc := wallet.NewService(stub, usableKey("unused"), nil, nil)

			if err := call(svc); !errors.Is(err, common.ErrNotFound) {
				t.Errorf("error = %v, want it to match %v", err, common.ErrNotFound)
			}
		})
	}
}

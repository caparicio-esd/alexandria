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
	gotPlan    *wallet.KeyPlan
	gotDidPlan *wallet.DidPlan
	err        error
}

func (s *stubWallet) Link(context.Context) (wallet.Did, error) {
	return wallet.Did{}, errors.New("not used in this test")
}

func (s *stubWallet) RegisterKey(_ context.Context, plan *wallet.KeyPlan) error {
	s.gotPlan = plan

	return s.err
}

func (s *stubWallet) RegisterDid(_ context.Context, plan *wallet.DidPlan) error {
	s.gotDidPlan = plan

	return s.err
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

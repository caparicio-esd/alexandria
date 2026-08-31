package wallet_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/google/uuid"
)

// stubWallet stands in for the outsourced wallet. It records the plan it was
// handed, which is the whole point: RegisterKey's job is minting that plan.
type stubWallet struct {
	gotPlan *wallet.KeyPlan
	err     error
}

func (s *stubWallet) Link(context.Context) (wallet.Did, error) {
	return wallet.Did{}, errors.New("not used in this test")
}

func (s *stubWallet) RegisterKey(_ context.Context, plan *wallet.KeyPlan) error {
	s.gotPlan = plan

	return s.err
}

// TestRegisterKeyMintsAPlan pins what the use case adds over the port: a fresh
// storage path per key, and the PEM passed through untouched.
func TestRegisterKeyMintsAPlan(t *testing.T) {
	t.Parallel()

	const pem = "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----\n"

	alias := "signing"
	stub := &stubWallet{}
	svc := wallet.NewService(stub, nil, nil)

	if err := svc.RegisterKey(t.Context(), pem, &alias); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	if stub.gotPlan == nil {
		t.Fatal("the wallet was never called")
	}

	if stub.gotPlan.Pem != pem {
		t.Errorf("plan.Pem = %q, want the pem it was handed", stub.gotPlan.Pem)
	}

	if stub.gotPlan.Alias != alias {
		t.Errorf("plan.Alias = %q, want %q", stub.gotPlan.Alias, alias)
	}

	// The id is the path the wallet writes the material to. It has to be both
	// unique — Fafnir will overwrite one key with another that shares it — and
	// flat, because its development vault does not create parent directories.
	id, ok := strings.CutSuffix(stub.gotPlan.ID, ".json")
	if !ok {
		t.Fatalf("plan.ID = %q, want a .json name", stub.gotPlan.ID)
	}

	if strings.Contains(id, "/") {
		t.Errorf("plan.ID = %q, want a flat name: a nested path fails the vault write", stub.gotPlan.ID)
	}

	if _, err := uuid.Parse(id); err != nil {
		t.Errorf("plan.ID = %q, want a uuid before the extension: %v", stub.gotPlan.ID, err)
	}
}

// TestRegisterKeyIDsAreUnique guards against a plan built from anything shared:
// two registrations must not collide on the storage path.
func TestRegisterKeyIDsAreUnique(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}
	svc := wallet.NewService(stub, nil, nil)

	if err := svc.RegisterKey(t.Context(), "pem", nil); err != nil {
		t.Fatalf("first RegisterKey: %v", err)
	}

	first := stub.gotPlan.ID

	if err := svc.RegisterKey(t.Context(), "pem", nil); err != nil {
		t.Fatalf("second RegisterKey: %v", err)
	}

	if stub.gotPlan.ID == first {
		t.Errorf("both registrations minted %q", first)
	}
}

// TestRegisterKeyWithoutAlias pins the nil alias: the wallet requires the field,
// so it goes out empty rather than absent.
func TestRegisterKeyWithoutAlias(t *testing.T) {
	t.Parallel()

	stub := &stubWallet{}
	svc := wallet.NewService(stub, nil, nil)

	if err := svc.RegisterKey(t.Context(), "pem", nil); err != nil {
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

	stub := &stubWallet{err: wallet.ErrConflict}
	svc := wallet.NewService(stub, nil, nil)

	err := svc.RegisterKey(t.Context(), "pem", nil)
	if !errors.Is(err, wallet.ErrConflict) {
		t.Errorf("error = %v, want it to match %v", err, wallet.ErrConflict)
	}
}

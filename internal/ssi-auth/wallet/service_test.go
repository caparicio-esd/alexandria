package wallet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/caparicio-esd/alexandria/internal/did"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

// ===== Doubles ===============================================================
//
// No mocking library: a struct of funcs is shorter than configuring a generator
// and reads as plain Go in the failure output.

type fakeKeys struct {
	byID map[string]wallet.Key
}

func (f fakeKeys) Store(context.Context, string, *string) (wallet.Key, error) {
	return wallet.Key{}, errors.New("not used")
}
func (f fakeKeys) List(context.Context) ([]wallet.Key, error) { return nil, nil }
func (f fakeKeys) Delete(context.Context, string) error       { return nil }

func (f fakeKeys) ByID(_ context.Context, id string) (wallet.Key, error) {
	k, ok := f.byID[id]
	if !ok {
		return wallet.Key{}, wallet.ErrNotFound
	}

	return k, nil
}

type fakeDids struct {
	stored  map[string]wallet.Did
	saveErr error
}

func (f *fakeDids) Save(_ context.Context, d wallet.Did) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.stored[d.ID.String()] = d

	return nil
}

func (f *fakeDids) ByID(_ context.Context, id string) (wallet.Did, error) {
	d, ok := f.stored[id]
	if !ok {
		return wallet.Did{}, wallet.ErrNotFound
	}

	return d, nil
}

func (f *fakeDids) Default(context.Context) (wallet.Did, error) {
	return wallet.Did{}, wallet.ErrNotFound
}
func (f *fakeDids) List(context.Context) ([]wallet.Did, error) { return nil, nil }
func (f *fakeDids) Delete(context.Context, string) error       { return nil }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var testNow = time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)

func newService(t *testing.T, keys map[string]wallet.Key) (*wallet.Service, *fakeDids) {
	t.Helper()

	dids := &fakeDids{stored: map[string]wallet.Did{}}

	return wallet.NewService(dids, fakeKeys{byID: keys}, nil, nil, fixedClock{t: testNow}), dids
}

func edKey(id string) wallet.Key {
	return wallet.Key{ID: id, Alg: common.AlgEdDSA, Thumbprint: "tp-" + id, CreatedAt: testNow}
}

// ===== Tests =================================================================

func TestRegisterDidWeb(t *testing.T) {
	t.Parallel()

	svc, dids := newService(t, map[string]wallet.Key{"k1": edKey("k1"), "k2": edKey("k2")})

	minted, err := svc.RegisterDid(context.Background(),
		wallet.DidBuilder{Method: did.MethodWeb, Domain: "wallet.example.org", Path: "/alice"},
		[]string{"k1", "k2"}, nil,
		[]did.Service{{ID: "#svc-1", Type: "LinkedDomains", Endpoint: "https://example.org"}},
	)
	if err != nil {
		t.Fatalf("RegisterDid: %v", err)
	}

	if want := "did:web:wallet.example.org:alice"; minted.ID.String() != want {
		t.Errorf("id = %q, want %q", minted.ID, want)
	}
	if len(minted.VerificationMethods) != 2 {
		t.Errorf("got %d verification methods, want 2", len(minted.VerificationMethods))
	}
	if minted.VerificationMethods[0].ID != minted.ID.String()+"#k1" {
		t.Errorf("verification method id = %q", minted.VerificationMethods[0].ID)
	}
	if minted.DefaultKeyID != "k1" {
		t.Errorf("default key = %q, want k1", minted.DefaultKeyID)
	}
	if !minted.CreatedAt.Equal(testNow) {
		t.Errorf("createdAt = %v, want the injected clock %v", minted.CreatedAt, testNow)
	}
	if _, ok := dids.stored[minted.ID.String()]; !ok {
		t.Error("the did was not persisted through the port")
	}
}

func TestRegisterDidRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		builder wallet.DidBuilder
		keysID  []string
		service []did.Service
		want    error
		field   string
	}{
		{
			name:    "unknown method",
			builder: wallet.DidBuilder{Method: "iota"},
			keysID:  []string{"k1"},
			want:    wallet.ErrUnsupported,
		},
		{
			name:    "no keys",
			builder: wallet.DidBuilder{Method: did.MethodWeb, Domain: "example.org"},
			keysID:  nil,
			want:    wallet.ErrInvalidInput,
			field:   "keys_id",
		},
		{
			name:    "unknown key",
			builder: wallet.DidBuilder{Method: did.MethodWeb, Domain: "example.org"},
			keysID:  []string{"ghost"},
			want:    wallet.ErrNotFound,
		},
		{
			name:    "duplicated key",
			builder: wallet.DidBuilder{Method: did.MethodWeb, Domain: "example.org"},
			keysID:  []string{"k1", "k1"},
			want:    wallet.ErrInvalidInput,
			field:   "keys_id[1]",
		},
		{
			name:    "did:key takes a single key",
			builder: wallet.DidBuilder{Method: did.MethodKey},
			keysID:  []string{"k1", "k2"},
			want:    wallet.ErrInvalidInput,
			field:   "keys_id",
		},
		{
			name:    "did:web without domain",
			builder: wallet.DidBuilder{Method: did.MethodWeb},
			keysID:  []string{"k1"},
			want:    wallet.ErrInvalidInput,
			field:   "builder.domain",
		},
		{
			name:    "domain carrying a scheme",
			builder: wallet.DidBuilder{Method: did.MethodWeb, Domain: "https://example.org"},
			keysID:  []string{"k1"},
			want:    wallet.ErrInvalidInput,
			field:   "builder.domain",
		},
		{
			name:    "duplicated service id",
			builder: wallet.DidBuilder{Method: did.MethodWeb, Domain: "example.org"},
			keysID:  []string{"k1"},
			service: []did.Service{
				{ID: "#s", Type: "T", Endpoint: "https://a"},
				{ID: "#s", Type: "T", Endpoint: "https://b"},
			},
			want:  wallet.ErrInvalidInput,
			field: "service[1].id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc, _ := newService(t, map[string]wallet.Key{"k1": edKey("k1"), "k2": edKey("k2")})

			_, err := svc.RegisterDid(context.Background(), tc.builder, tc.keysID, nil, tc.service)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}

			if tc.field != "" {
				var v wallet.ValidationError
				if !errors.As(err, &v) {
					t.Fatalf("err %v is not a ValidationError", err)
				}
				if v.Field != tc.field {
					t.Errorf("field = %q, want %q", v.Field, tc.field)
				}
			}
		})
	}
}

func TestRegisterDidConflict(t *testing.T) {
	t.Parallel()

	svc, _ := newService(t, map[string]wallet.Key{"k1": edKey("k1")})
	builder := wallet.DidBuilder{Method: did.MethodWeb, Domain: "example.org"}

	if _, err := svc.RegisterDid(context.Background(), builder, []string{"k1"}, nil, nil); err != nil {
		t.Fatalf("first RegisterDid: %v", err)
	}

	_, err := svc.RegisterDid(context.Background(), builder, []string{"k1"}, nil, nil)
	if !errors.Is(err, wallet.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestRegisterDidWrapsRepositoryFailure(t *testing.T) {
	t.Parallel()

	boom := errors.New("connection refused")
	dids := &fakeDids{stored: map[string]wallet.Did{}, saveErr: boom}
	svc := wallet.NewService(dids, fakeKeys{byID: map[string]wallet.Key{"k1": edKey("k1")}},
		nil, nil, fixedClock{t: testNow})

	_, err := svc.RegisterDid(context.Background(),
		wallet.DidBuilder{Method: did.MethodWeb, Domain: "example.org"},
		[]string{"k1"}, nil, nil)

	// Infrastructure failures stay wrapped and match none of the sentinels, so
	// the REST adapter answers 500 instead of leaking a driver error as a 4xx.
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
	for _, sentinel := range []error{wallet.ErrInvalidInput, wallet.ErrNotFound, wallet.ErrConflict} {
		if errors.Is(err, sentinel) {
			t.Errorf("infrastructure error must not match %v", sentinel)
		}
	}
}

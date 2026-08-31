package fafnir_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/fafnir"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

// keyRecord is a real Fafnir key record: the columns of its "keys" table, in
// the spelling it puts on the wire.
const keyRecord = `{
	"id": "8d1c1f7e-3f0e-11f0-9c1a-0242ac120002.json",
	"alias": "base",
	"kty": "OKP",
	"crv": "Ed25519",
	"created_at": "2026-08-21T18:42:05.326269Z"
}`

// TestRegisterKeyCall pins the request half of the contract. Fafnir answers
// GET /keys/new with 405, so a wrong verb or a missing body fails against the
// real wallet and against nothing else — this is where it gets caught.
func TestRegisterKeyCall(t *testing.T) {
	t.Parallel()

	var (
		gotMethod string
		gotPath   string
		gotBody   map[string]any
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path

		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, keyRecord)
	}))
	defer srv.Close()

	adapter, err := fafnir.New(srv.URL, nil)
	if err != nil {
		t.Fatalf("building adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	plan := &wallet.KeyPlan{
		ID:    "8d1c1f7e-3f0e-11f0-9c1a-0242ac120002.json",
		Alias: "base",
		Pem:   "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----\n",
	}

	if err := adapter.RegisterKey(t.Context(), plan); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want %q", gotMethod, http.MethodPost)
	}

	if gotPath != "/keys/new" {
		t.Errorf("path = %q, want %q", gotPath, "/keys/new")
	}

	// Fafnir names the storage path "id" and the material "pem"; nothing else
	// identifies the key, so an empty body is a silent no-op registration.
	for field, want := range map[string]string{
		"id":    plan.ID,
		"alias": plan.Alias,
		"pem":   plan.Pem,
	} {
		if got, _ := gotBody[field].(string); got != want {
			t.Errorf("body[%q] = %q, want %q", field, got, want)
		}
	}
}

// TestRegisterKeyChecksTheRecord pins what the adapter still does with the
// answer now that the port discards it: a record it cannot map — here a "kty"
// that is not in the JWA registry — is a failed registration, not a silent one.
func TestRegisterKeyChecksTheRecord(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		body    string
		wantErr bool
	}{
		"a filed key":    {keyRecord, false},
		"rsa, no curve":  {`{"id":"a.json","alias":"base","kty":"RSA","crv":null,"created_at":"2026-08-21T18:42:05Z"}`, false},
		"nothing behind": {`{}`, true},
		"unknown kty":    {`{"id":"a.json","kty":"octet","created_at":"2026-08-21T18:42:05Z"}`, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			adapter, err := fafnir.New(srv.URL, nil)
			if err != nil {
				t.Fatalf("building adapter: %v", err)
			}
			defer func() { _ = adapter.Close() }()

			err = adapter.RegisterKey(t.Context(), &wallet.KeyPlan{ID: "a.json", Alias: "base", Pem: "pem"})
			if tc.wantErr && err == nil {
				t.Error("expected the record to be rejected")
			}

			if !tc.wantErr && err != nil {
				t.Errorf("RegisterKey: %v", err)
			}
		})
	}
}

// TestRegisterKeyStatusErrors maps the statuses onto the wallet sentinels, so a
// caller can branch on them without knowing HTTP exists.
func TestRegisterKeyStatusErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status int
		want   error
	}{
		"malformed payload": {http.StatusBadRequest, wallet.ErrInvalidInput},
		"alias taken":       {http.StatusConflict, wallet.ErrConflict},
		"wrong verb":        {http.StatusMethodNotAllowed, nil},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"message":"Format Error","error_code":3120}`)
			}))
			defer srv.Close()

			adapter, err := fafnir.New(srv.URL, nil)
			if err != nil {
				t.Fatalf("building adapter: %v", err)
			}
			defer func() { _ = adapter.Close() }()

			err = adapter.RegisterKey(t.Context(), &wallet.KeyPlan{ID: "a.json"})
			if err == nil {
				t.Fatalf("status %d: expected an error", tc.status)
			}

			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want it to match %v", err, tc.want)
			}
		})
	}
}

// TestRegisterKeyRejectsNilPlan guards the one input the port cannot describe:
// a nil plan would otherwise register an empty key under an empty path.
func TestRegisterKeyRejectsNilPlan(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("the wallet was called with a nil plan")
	}))
	defer srv.Close()

	adapter, err := fafnir.New(srv.URL, nil)
	if err != nil {
		t.Fatalf("building adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	if err := adapter.RegisterKey(t.Context(), nil); !errors.Is(err, wallet.ErrInvalidInput) {
		t.Errorf("error = %v, want it to match %v", err, wallet.ErrInvalidInput)
	}
}

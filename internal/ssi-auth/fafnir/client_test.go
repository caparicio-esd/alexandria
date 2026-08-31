package fafnir_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/common"
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

// TestRegisterKeyStatusErrors pins the translation of HTTP statuses onto the
// domain sentinels, so a caller can branch on them without knowing HTTP exists.
func TestRegisterKeyStatusErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status int
		want   error
	}{
		"malformed payload": {http.StatusBadRequest, common.ErrInvalidInput},
		"alias taken":       {http.StatusConflict, common.ErrConflict},
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

	if err := adapter.RegisterKey(t.Context(), nil); !errors.Is(err, common.ErrInvalidInput) {
		t.Errorf("error = %v, want it to match %v", err, common.ErrInvalidInput)
	}
}

// ===== GetAllKeys ============================================================

// TestGetAllKeysCall pins the request half: Fafnir lists the vault under
// /keys/all, and GET /keys is a different endpoint on the real wallet.
func TestGetAllKeysCall(t *testing.T) {
	t.Parallel()

	var (
		gotMethod string
		gotPath   string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "["+keyRecord+"]")
	}))
	defer srv.Close()

	adapter, err := fafnir.New(srv.URL, nil)
	if err != nil {
		t.Fatalf("building adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	keys, err := adapter.GetAllKeys(t.Context())
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want %q", gotMethod, http.MethodGet)
	}

	if gotPath != "/keys/all" {
		t.Errorf("path = %q, want %q", gotPath, "/keys/all")
	}

	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}

	// Fafnir spells the timestamp "created_at"; the domain field is CreatedAt,
	// so a wrong tag would leave it silently zero.
	got := keys[0]
	if got.ID != "8d1c1f7e-3f0e-11f0-9c1a-0242ac120002.json" {
		t.Errorf("id = %q, want the record's own", got.ID)
	}

	if got.Alias != "base" {
		t.Errorf("alias = %q, want %q", got.Alias, "base")
	}

	if got.Kty != "OKP" {
		t.Errorf("kty = %q, want %q", got.Kty, "OKP")
	}

	if got.Crv == nil || *got.Crv != "Ed25519" {
		t.Errorf("crv = %v, want %q", got.Crv, "Ed25519")
	}

	if got.CreatedAt.IsZero() {
		t.Error("createdAt is zero: the record's created_at never made it into the domain")
	}
}

// TestGetAllKeysOnAnEmptyVault keeps "no keys" a success with an empty slice: an
// empty wallet is an ordinary state, not a failure and not a nil the caller has
// to guard.
func TestGetAllKeysOnAnEmptyVault(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[]`)
	}))
	defer srv.Close()

	adapter, err := fafnir.New(srv.URL, nil)
	if err != nil {
		t.Fatalf("building adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	keys, err := adapter.GetAllKeys(t.Context())
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}

	if keys == nil {
		t.Fatal("keys = nil, want an empty slice")
	}

	if len(keys) != 0 {
		t.Errorf("got %d keys, want none", len(keys))
	}
}

// TestGetAllKeysRejectsUnusableRecords stops a record the domain cannot name or
// classify from being handed on as a usable key.
func TestGetAllKeysRejectsUnusableRecords(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"no id":         `[{"id":"","kty":"OKP","crv":"Ed25519"}]`,
		"unknown kty":   `[{"id":"a.json","kty":"MAGIC"}]`,
		"unknown curve": `[{"id":"a.json","kty":"OKP","crv":"P-1"}]`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()

			adapter, err := fafnir.New(srv.URL, nil)
			if err != nil {
				t.Fatalf("building adapter: %v", err)
			}
			defer func() { _ = adapter.Close() }()

			if _, err := adapter.GetAllKeys(t.Context()); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// TestGetAllKeysStatusErrors pins the translation of HTTP statuses onto the
// domain sentinels for the listing call.
func TestGetAllKeysStatusErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status int
		want   error
	}{
		"no vault":    {http.StatusNotFound, common.ErrNotFound},
		"wrong verb":  {http.StatusMethodNotAllowed, nil},
		"wallet down": {http.StatusInternalServerError, nil},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"message":"Not Found","error_code":3110}`)
			}))
			defer srv.Close()

			adapter, err := fafnir.New(srv.URL, nil)
			if err != nil {
				t.Fatalf("building adapter: %v", err)
			}
			defer func() { _ = adapter.Close() }()

			keys, err := adapter.GetAllKeys(t.Context())
			if err == nil {
				t.Fatalf("status %d: expected an error", tc.status)
			}

			if keys != nil {
				t.Errorf("keys = %v alongside an error, want nil", keys)
			}

			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want it to match %v", err, tc.want)
			}
		})
	}
}

// ===== DeleteKey / DeleteDid =================================================

// TestDeleteCalls pins the verb and the path of both deletions. Keys and DIDs
// are separate collections in Fafnir, so a swapped prefix deletes the wrong
// record — or, more often, answers 404 for one that is plainly there.
func TestDeleteCalls(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		id   string
		call func(*fafnir.Adapter, string) error
		want string
	}{
		"key": {
			id:   "8d1c1f7e-3f0e-11f0-9c1a-0242ac120002.json",
			call: func(a *fafnir.Adapter, id string) error { return a.DeleteKey(t.Context(), id) },
			want: "/keys/8d1c1f7e-3f0e-11f0-9c1a-0242ac120002.json",
		},
		"did": {
			id:   "did:web:alexandria.upm.es",
			call: func(a *fafnir.Adapter, id string) error { return a.DeleteDid(t.Context(), id) },
			want: "/dids/did:web:alexandria.upm.es",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				gotMethod string
				gotPath   string
			)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path

				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			adapter, err := fafnir.New(srv.URL, nil)
			if err != nil {
				t.Fatalf("building adapter: %v", err)
			}
			defer func() { _ = adapter.Close() }()

			if err := tc.call(adapter, tc.id); err != nil {
				t.Fatalf("delete: %v", err)
			}

			if gotMethod != http.MethodDelete {
				t.Errorf("method = %q, want %q", gotMethod, http.MethodDelete)
			}

			if gotPath != tc.want {
				t.Errorf("path = %q, want %q", gotPath, tc.want)
			}
		})
	}
}

// TestDeleteStatusErrors pins the sentinels for both deletions, so the REST
// layer renders a 404 for a record that is not there rather than a 500.
func TestDeleteStatusErrors(t *testing.T) {
	t.Parallel()

	calls := map[string]func(*fafnir.Adapter) error{
		"key": func(a *fafnir.Adapter) error { return a.DeleteKey(t.Context(), "missing.json") },
		"did": func(a *fafnir.Adapter) error { return a.DeleteDid(t.Context(), "did:web:missing") },
	}

	statuses := map[string]struct {
		status int
		want   error
	}{
		"absent":       {http.StatusNotFound, common.ErrNotFound},
		"still bound":  {http.StatusConflict, common.ErrConflict},
		"malformed id": {http.StatusBadRequest, common.ErrInvalidInput},
		"wrong verb":   {http.StatusMethodNotAllowed, nil},
	}

	for target, call := range calls {
		for name, tc := range statuses {
			t.Run(target+"/"+name, func(t *testing.T) {
				t.Parallel()

				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, `{"message":"Not Found","error_code":3110}`)
				}))
				defer srv.Close()

				adapter, err := fafnir.New(srv.URL, nil)
				if err != nil {
					t.Fatalf("building adapter: %v", err)
				}
				defer func() { _ = adapter.Close() }()

				err = call(adapter)
				if err == nil {
					t.Fatalf("status %d: expected an error", tc.status)
				}

				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Errorf("error = %v, want it to match %v", err, tc.want)
				}
			})
		}
	}
}

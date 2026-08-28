package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
)

type ctx = context.Context

// The router is exercised against a real wallet.Service backed by in-memory
// ports: the seam worth faking is the outbound one, not the use case.

type memKeys struct{ k map[string]wallet.Key }

func (m memKeys) Store(_ ctx, _ string, _ *string) (wallet.Key, error) {
	return wallet.Key{}, wallet.ErrUnsupported
}
func (m memKeys) List(ctx) ([]wallet.Key, error) { return nil, nil }
func (m memKeys) Delete(ctx, string) error       { return nil }
func (m memKeys) ByID(_ ctx, id string) (wallet.Key, error) {
	if k, ok := m.k[id]; ok {
		return k, nil
	}

	return wallet.Key{}, wallet.ErrNotFound
}

type memDids struct{ d map[string]wallet.Did }

func (m memDids) Save(_ ctx, d wallet.Did) error { m.d[d.ID.String()] = d; return nil }
func (m memDids) ByID(_ ctx, id string) (wallet.Did, error) {
	if d, ok := m.d[id]; ok {
		return d, nil
	}

	return wallet.Did{}, wallet.ErrNotFound
}
func (m memDids) Default(ctx) (wallet.Did, error) { return wallet.Did{}, wallet.ErrNotFound }
func (m memDids) List(ctx) ([]wallet.Did, error)  { return nil, nil }
func (m memDids) Delete(ctx, string) error        { return nil }

type frozen struct{}

func (frozen) Now() time.Time { return time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC) }

func newEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	keys := memKeys{k: map[string]wallet.Key{
		"k1": {ID: "k1", Alg: common.AlgEdDSA, Thumbprint: "tp-k1"},
	}}
	svc := wallet.NewService(memDids{d: map[string]wallet.Did{}}, keys, nil, nil, frozen{})

	engine := gin.New()
	rest.NewCoreRouter(rest.NewWalletRouter(svc)).Register(engine)

	return engine
}

func post(t *testing.T, engine *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(),
		http.MethodPost, "/ssi-auth/wallet/did", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

func TestRegisterDidCreated(t *testing.T) {
	t.Parallel()

	rec := post(t, newEngine(t), `{
		"builder": {"method": "web", "domain": "wallet.example.org", "path": "/alice"},
		"keys_id": ["k1"],
		"alias": "primary",
		"service": [{"id": "#svc", "type": "LinkedDomains", "endpoint": "https://example.org"}]
	}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body: %v", err)
	}

	if got["id"] != "did:web:wallet.example.org:alice" {
		t.Errorf("id = %v", got["id"])
	}
	if got["default_key_id"] != "k1" {
		t.Errorf("default_key_id = %v", got["default_key_id"])
	}
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Error("missing Location header")
	}

	// The wire contract is a closed set: nothing the domain grows leaks by default.
	allowed := map[string]bool{
		"id": true, "method": true, "alias": true, "verification_methods": true,
		"services": true, "default_key_id": true, "created_at": true,
	}
	for k := range got {
		if !allowed[k] {
			t.Errorf("unexpected field %q in the response", k)
		}
	}
}

func TestRegisterDidErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		body  string
		want  int
		field string
	}{
		{"malformed json", `{`, http.StatusBadRequest, ""},
		{
			"missing keys",
			`{"builder": {"method": "web", "domain": "example.org"}, "keys_id": []}`,
			http.StatusBadRequest, "",
		},
		{
			"unknown key",
			`{"builder": {"method": "web", "domain": "example.org"}, "keys_id": ["ghost"]}`,
			http.StatusNotFound, "",
		},
		{
			"unsupported method",
			`{"builder": {"method": "iota"}, "keys_id": ["k1"]}`,
			http.StatusUnprocessableEntity, "",
		},
		{
			"domain with scheme",
			`{"builder": {"method": "web", "domain": "https://example.org"}, "keys_id": ["k1"]}`,
			http.StatusBadRequest, "builder.domain",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := post(t, newEngine(t), tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.want, rec.Body)
			}

			if tc.field != "" {
				var body struct {
					Field string `json:"field"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decoding body: %v", err)
				}
				if body.Field != tc.field {
					t.Errorf("field = %q, want %q", body.Field, tc.field)
				}
			}
		})
	}
}

func TestRegisterDidConflict(t *testing.T) {
	t.Parallel()

	engine := newEngine(t)
	body := `{"builder": {"method": "web", "domain": "example.org"}, "keys_id": ["k1"]}`

	if rec := post(t, engine, body); rec.Code != http.StatusCreated {
		t.Fatalf("first call: %d %s", rec.Code, rec.Body)
	}
	if rec := post(t, engine, body); rec.Code != http.StatusConflict {
		t.Fatalf("second call: %d %s", rec.Code, rec.Body)
	}
}

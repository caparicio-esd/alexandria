package did_test

import (
	"errors"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/did"
)

func TestNewWeb(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, domain, path, want string
		wantErr                  error
	}{
		{name: "bare domain", domain: "example.org", want: "did:web:example.org"},
		{name: "with path", domain: "example.org", path: "/alice", want: "did:web:example.org:alice"},
		{name: "nested path", domain: "example.org", path: "users/alice/", want: "did:web:example.org:users:alice"},
		{name: "empty domain", wantErr: did.ErrMalformed},
		{name: "scheme", domain: "https://example.org", wantErr: did.ErrMalformed},
		{name: "port", domain: "example.org:8443", wantErr: did.ErrMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := did.NewWeb(tc.domain, tc.path)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("NewWeb: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("did = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"did:web:example.org", "did:web:example.org:alice", "did:key:z6Mk"} {
		got, err := did.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if got.String() != raw {
			t.Errorf("round trip: %q -> %q", raw, got)
		}
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want error
	}{
		{"", did.ErrMalformed},
		{"example.org", did.ErrMalformed},
		{"did:web", did.ErrMalformed},
		{"did::alice", did.ErrMalformed},
		{"urn:web:example.org", did.ErrMalformed},
		{"did:iota:abc", did.ErrUnsupportedMethod},
	}

	for _, tc := range cases {
		if _, err := did.Parse(tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("Parse(%q) err = %v, want %v", tc.raw, err, tc.want)
		}
	}
}

func TestValidateServices(t *testing.T) {
	t.Parallel()

	ok := []did.Service{{ID: "#a", Type: "T", Endpoint: "https://a"}}
	if err := did.ValidateServices(ok); err != nil {
		t.Fatalf("valid services rejected: %v", err)
	}

	cases := []struct {
		name      string
		services  []did.Service
		index     int
		component string
	}{
		{"empty id", []did.Service{{Type: "T", Endpoint: "https://a"}}, 0, "id"},
		{"empty type", []did.Service{{ID: "#a", Endpoint: "https://a"}}, 0, "type"},
		{"empty endpoint", []did.Service{{ID: "#a", Type: "T"}}, 0, "endpoint"},
		{
			"duplicated id",
			[]did.Service{
				{ID: "#a", Type: "T", Endpoint: "https://a"},
				{ID: "#a", Type: "T", Endpoint: "https://b"},
			},
			1, "id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var svcErr did.ServiceError
			if err := did.ValidateServices(tc.services); !errors.As(err, &svcErr) {
				t.Fatalf("err = %v, want a ServiceError", err)
			}
			if svcErr.Index != tc.index || svcErr.Component != tc.component {
				t.Errorf("got [%d].%s, want [%d].%s",
					svcErr.Index, svcErr.Component, tc.index, tc.component)
			}
		})
	}
}

func TestNewDocument(t *testing.T) {
	t.Parallel()

	id, err := did.NewWeb("example.org", "")
	if err != nil {
		t.Fatalf("NewWeb: %v", err)
	}

	doc := did.NewDocument(id,
		[]did.VerificationMethod{{ID: id.Fragment("k1"), KeyRef: "k1"}},
		[]did.Service{{ID: "#a", Type: "T", Endpoint: "https://a"}})

	if doc.ID != "did:web:example.org" {
		t.Errorf("doc id = %q", doc.ID)
	}
	if len(doc.Context) != 1 || doc.Context[0] != did.ContextV1 {
		t.Errorf("context = %v", doc.Context)
	}
	if len(doc.Authentication) != 1 || doc.Authentication[0] != "did:web:example.org#k1" {
		t.Errorf("authentication = %v", doc.Authentication)
	}
}

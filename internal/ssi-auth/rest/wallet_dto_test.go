// This file is in package rest rather than rest_test because didBuilderReq and
// its decoding are unexported: the wire format of the union is exactly what is
// worth pinning down, and it is not reachable from outside.
package rest

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/common"
)

func TestDidBuilderReqDecodesJwk(t *testing.T) {
	t.Parallel()

	var req registerDidReq
	if err := json.Unmarshal([]byte(`{
		"builder": {"method": "jwk", "pem": "-----BEGIN PRIVATE KEY-----"},
		"keys_id": "k1"
	}`), &req); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	builder, err := req.Builder.toDomain()
	if err != nil {
		t.Fatalf("to domain: %v", err)
	}

	jwkBuilder, ok := builder.(common.JwkDidBuilder)
	if !ok {
		t.Fatalf("got %T, want wallet.JwkDidBuilder", builder)
	}

	if jwkBuilder.Pem != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("pem did not survive decoding: %q", jwkBuilder.Pem)
	}
}

func TestDidBuilderReqDecodesWebWithoutOptionals(t *testing.T) {
	t.Parallel()

	var req registerDidReq
	if err := json.Unmarshal([]byte(`{
		"builder": {"method": "web", "domain": "alexandria.upm.es"}
	}`), &req); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	builder, err := req.Builder.toDomain()
	if err != nil {
		t.Fatalf("to domain: %v", err)
	}

	webBuilder, ok := builder.(common.WebDidBuilder)
	if !ok {
		t.Fatalf("got %T, want wallet.WebDidBuilder", builder)
	}

	// Absent, not empty: the distinction is the reason these are pointers.
	if webBuilder.Port != nil || webBuilder.Path != nil {
		t.Errorf("omitted members should decode to nil, got port=%v path=%v",
			webBuilder.Port, webBuilder.Path)
	}
}

func TestDidBuilderReqRejectsUnknownMethod(t *testing.T) {
	t.Parallel()

	var req registerDidReq

	err := json.Unmarshal([]byte(`{"builder": {"method": "ion", "domain": "x"}}`), &req)
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("got %v, want wallet.ErrUnsupported", err)
	}
}

func TestDidBuilderReqRejectsMissingBuilder(t *testing.T) {
	t.Parallel()

	var req registerDidReq
	if err := json.Unmarshal([]byte(`{"keys_id": "k1"}`), &req); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if _, err := req.Builder.toDomain(); !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("got %v, want wallet.ErrInvalidInput", err)
	}
}

func TestDidBuilderReqRejectsEmptyOptional(t *testing.T) {
	t.Parallel()

	var req registerDidReq
	if err := json.Unmarshal([]byte(`{
		"builder": {"method": "web", "domain": "alexandria.upm.es", "port": ""}
	}`), &req); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if _, err := req.Builder.toDomain(); !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("got %v, want wallet.ErrInvalidInput", err)
	}
}

func TestDidServiceDecodesUnknownTypeVerbatim(t *testing.T) {
	t.Parallel()

	var req registerDidReq
	if err := json.Unmarshal([]byte(`{
		"builder": {"method": "web", "domain": "alexandria.upm.es"},
		"service": [
			{"type": "CredentialIssuer", "serviceEndpoint": "https://alexandria.upm.es/vci"},
			{"type": "LinkedDomains", "serviceEndpoint": "https://alexandria.upm.es"}
		]
	}`), &req); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	services, err := servicesToDomain(req.Service)
	if err != nil {
		t.Fatalf("to domain: %v", err)
	}

	if !services[0].Type.Known() {
		t.Error("CredentialIssuer should be a known service type")
	}

	// The point of the open vocabulary: a type this project does not act on is
	// carried through rather than rejected.
	if services[1].Type.Known() {
		t.Error("LinkedDomains should not be reported as known")
	}

	if services[1].Type != "LinkedDomains" {
		t.Errorf("unknown type did not survive: %q", services[1].Type)
	}
}

func TestDidServiceRejectsEntryWithoutEndpoint(t *testing.T) {
	t.Parallel()

	var req registerDidReq
	if err := json.Unmarshal([]byte(`{
		"builder": {"method": "web", "domain": "alexandria.upm.es"},
		"service": [{"type": "CredentialIssuer"}]
	}`), &req); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if _, err := servicesToDomain(req.Service); !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("got %v, want wallet.ErrInvalidInput", err)
	}
}

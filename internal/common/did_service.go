package common

import (
	"strings"
)

// DidServiceType is the role a service entry plays in a DID Document.
//
// The vocabulary is open by design: DID Core lets anyone define a type, so an
// unrecognised one is carried through verbatim rather than rejected. Known
// reports whether this project acts on it — see the constants below.
type DidServiceType string

const (
	// ServiceAuthorizationServer is the OAuth 2.0 authorization server.
	ServiceAuthorizationServer DidServiceType = "AuthorizationServer"
	// ServiceCredentialIssuer is the OID4VCI credential issuer.
	//nolint:gosec // G101 reads "CredentialIssuer" as a secret; it is a service
	// type name published in a DID Document, and there is nothing to leak.
	ServiceCredentialIssuer DidServiceType = "CredentialIssuer"
	// ServiceFederatedCatalog is the vocabulary catalogue this project federates.
	ServiceFederatedCatalog DidServiceType = "FederatedCatalog"
)

// Known reports whether this build recognises the type. It informs, it does not
// gate: an unknown type is still a publishable entry, just not one this project
// knows how to act on.
func (t DidServiceType) Known() bool {
	switch t {
	case
		ServiceAuthorizationServer,
		ServiceCredentialIssuer,
		ServiceFederatedCatalog:
		return true
	default:
		return false
	}
}

func (t DidServiceType) String() string { return string(t) }

// DidService is a service entry to publish in a DID Document.
type DidService struct {
	ID string
	// Type is the role the endpoint plays.
	Type DidServiceType
	// Endpoint is where the service answers.
	Endpoint string
}

// Validate reports whether the entry is publishable.
func (s DidService) Validate() error {
	if strings.TrimSpace(string(s.Type)) == "" {
		return Invalid("service.type", "is required")
	}

	if strings.TrimSpace(s.Endpoint) == "" {
		return Invalid("service.serviceEndpoint", "is required")
	}

	return nil
}

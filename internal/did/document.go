package did

import (
	"strings"

	"github.com/caparicio-esd/alexandria/internal/common"
)

// VerificationMethod binds a public key into a DID Document.
type VerificationMethod struct {
	// ID is the fully qualified DID URL, e.g. did:web:example.org#key-1.
	ID  string
	Alg common.Alg
	// KeyRef points at the key material in whatever store the owner uses. It is
	// opaque to this package.
	KeyRef string
}

// Service is a service entry published in a DID Document.
type Service struct {
	ID       string
	Type     string
	Endpoint string
}

// Document is the resolvable form of a DID.
type Document struct {
	Context            []string
	ID                 string
	VerificationMethod []VerificationMethod
	Authentication     []string
	Service            []Service
}

// ContextV1 is the JSON-LD context every document this package builds declares.
const ContextV1 = "https://www.w3.org/ns/did/v1"

// NewDocument assembles the resolvable document for an identifier, listing every
// verification method as an authentication method.
func NewDocument(id DID, vms []VerificationMethod, services []Service) Document {
	auth := make([]string, 0, len(vms))
	for _, vm := range vms {
		auth = append(auth, vm.ID)
	}

	return Document{
		Context:            []string{ContextV1},
		ID:                 id.String(),
		VerificationMethod: vms,
		Authentication:     auth,
		Service:            services,
	}
}

// ValidateServices rejects malformed or duplicated service entries, reporting
// the offending index so callers can map it onto their own field names.
func ValidateServices(services []Service) error {
	seen := make(map[string]struct{}, len(services))

	for i, s := range services {
		switch {
		case strings.TrimSpace(s.ID) == "":
			return ServiceError{Index: i, Component: "id", Reason: "must not be empty"}
		case strings.TrimSpace(s.Type) == "":
			return ServiceError{Index: i, Component: "type", Reason: "must not be empty"}
		case strings.TrimSpace(s.Endpoint) == "":
			return ServiceError{Index: i, Component: "endpoint", Reason: "must not be empty"}
		}

		if _, dup := seen[s.ID]; dup {
			return ServiceError{
				Index: i, Component: "id", Reason: "duplicated service id " + s.ID,
			}
		}
		seen[s.ID] = struct{}{}
	}

	return nil
}

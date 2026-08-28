package rest

import (
	"time"

	"github.com/caparicio-esd/alexandria/internal/did"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

// This file owns the wire contract, and nothing else does.
//
// Domain types deliberately carry no json tags: a field added to wallet.Did
// must be written out here before it can reach a client, so widening the public
// API is always a visible, reviewable diff.

// ===== Requests ==============================================================

// registerKeyReq imports raw asymmetric private key material.
type registerKeyReq struct {
	// PEM is the raw private key; alg and curve are derived from it wallet-side.
	PEM string `json:"pem" binding:"required"`
	// Alias is a human-readable tag used to index the keypair.
	Alias *string `json:"alias"`
}

// didBuilderReq selects the DID method and its parameters.
type didBuilderReq struct {
	Method string `json:"method" binding:"required"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// toDomain maps the wire shape onto the domain builder.
func (b didBuilderReq) toDomain() wallet.DidBuilder {
	return wallet.DidBuilder{
		Method: did.Method(b.Method),
		Domain: b.Domain,
		Path:   b.Path,
	}
}

// didServiceReq is a service entry to publish in the DID Document.
type didServiceReq struct {
	ID       string `json:"id" binding:"required"`
	Type     string `json:"type" binding:"required"`
	Endpoint string `json:"endpoint" binding:"required"`
}

// registerDidReq mints a local DID bound to already-registered keys.
type registerDidReq struct {
	Builder didBuilderReq   `json:"builder" binding:"required"`
	KeysID  []string        `json:"keys_id" binding:"required,min=1"`
	Alias   *string         `json:"alias"`
	Service []didServiceReq `json:"service"`
}

// toDomainServices maps the service entries onto their domain counterparts.
func (r registerDidReq) toDomainServices() []did.Service {
	if len(r.Service) == 0 {
		return nil
	}

	out := make([]did.Service, 0, len(r.Service))
	for _, s := range r.Service {
		out = append(out, did.Service{ID: s.ID, Type: s.Type, Endpoint: s.Endpoint})
	}

	return out
}

// ===== Responses =============================================================

// verificationMethodResp is a key bound into a DID.
type verificationMethodResp struct {
	ID    string `json:"id"`
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
}

// didServiceResp is a published service entry.
type didServiceResp struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

// didResp is the public representation of a wallet DID.
type didResp struct {
	ID                  string                   `json:"id"`
	Method              string                   `json:"method"`
	Alias               string                   `json:"alias,omitempty"`
	VerificationMethods []verificationMethodResp `json:"verification_methods"`
	Services            []didServiceResp         `json:"services,omitempty"`
	DefaultKeyID        string                   `json:"default_key_id"`
	CreatedAt           time.Time                `json:"created_at"`
}

// newDidResp projects a domain DID onto the wire.
func newDidResp(d wallet.Did) didResp {
	vms := make([]verificationMethodResp, 0, len(d.VerificationMethods))
	for _, vm := range d.VerificationMethods {
		vms = append(vms, verificationMethodResp{ID: vm.ID, KeyID: vm.KeyRef, Alg: string(vm.Alg)})
	}

	var services []didServiceResp
	for _, s := range d.Services {
		services = append(services, didServiceResp{ID: s.ID, Type: s.Type, Endpoint: s.Endpoint})
	}

	return didResp{
		ID:                  d.ID.String(),
		Method:              string(d.ID.Method),
		Alias:               d.Alias,
		VerificationMethods: vms,
		Services:            services,
		DefaultKeyID:        d.DefaultKeyID,
		CreatedAt:           d.CreatedAt,
	}
}

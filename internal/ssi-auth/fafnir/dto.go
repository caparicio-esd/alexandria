package fafnir

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/jose"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/trustbloc/did-go/doc/did"
)

type didResp struct {
	// ID is the record identifier inside Fafnir, not the DID itself.
	ID string `json:"id"`
	// Did is the identifier proper, e.g. "did:web:alexandria.upm.es".
	Did string `json:"did"`
	// Alias is the human-readable tag the DID was registered under.
	Alias string `json:"alias"`
	// Default reports whether this is the wallet active identity.
	Default bool `json:"default"`
	// Type is the DID method as Fafnir spells it: "jwk" or "web".
	Type string `json:"type"`
	// Keys lists every key bound into the DID verification methods.
	Keys []keyRef `json:"keys"`
	// DefaultKey is the key used for signing unless told otherwise.
	DefaultKey keyRef `json:"default_key"`
	// DidDocument is held raw on purpose. did.Doc validates against DID Core on
	// unmarshal, so decoding it inline would make one malformed document throw
	// away the whole record — id, alias, keys and all. Call Doc to parse it.
	DidDocument json.RawMessage `json:"did_document"`
	// Service holds the published service entries. Fafnir sends null when there
	// are none, which decodes to a nil slice.
	Service []did.Service `json:"service,omitempty"`
}

// keyRef is how Fafnir points at a stored key: an internal storage path plus the
// fragment the key is published under in the DID Document.
type keyRef struct {
	Internal string `json:"internal"`
	Fragment string `json:"fragment"`
}

// ToDomain maps the Fafnir record onto the wallet domain entity.
//
// This is the anti-corruption boundary: Fafnir's spellings ("Jwk"), its storage
// paths and its non-conformant documents are dealt with here, and the domain
// receives something it defined itself.
func (d didResp) ToDomain() (wallet.Did, error) {
	method, err := wallet.ParseMethod(d.Type)
	if err != nil {
		return wallet.Did{}, fmt.Errorf("fafnir: did %q: %w", d.Did, err)
	}

	doc, err := d.doc()
	if err != nil {
		return wallet.Did{}, fmt.Errorf("fafnir: did %q: %w", d.Did, err)
	}

	keys := make([]wallet.KeyBinding, 0, len(d.Keys))
	for _, k := range d.Keys {
		keys = append(keys, k.toDomain())
	}

	return wallet.Did{
		ID:         d.Did,
		Method:     method,
		Alias:      d.Alias,
		Default:    d.Default,
		Document:   *doc,
		Keys:       keys,
		DefaultKey: d.DefaultKey.toDomain(),
	}, nil
}

// doc normalizes and parses the embedded DID Document.
//
// Transport and content fail separately by design: an unmarshalling error on
// didResp means Fafnir sent something unreadable, while an error here means the
// document itself does not conform.
func (d didResp) doc() (*did.Doc, error) {
	normalized, err := normalizeDidDocument(d.DidDocument)
	if err != nil {
		return nil, err
	}

	return did.ParseDocument(normalized)
}

// toDomain drops the storage path into the domain as an opaque key id: only the
// wallet that issued it knows how to resolve it back to key material.
func (k keyRef) toDomain() wallet.KeyBinding {
	return wallet.KeyBinding{KeyID: k.Internal, Fragment: k.Fragment}
}

// keyReq is the wire form of a key registration. Fafnir spells the storage
// path "id" — the same value it later hands back as keyRef.Internal — and takes
// the material as PEM.
type keyReq struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
	Pem   string `json:"pem"`
}

// newKeyReq projects a domain key plan onto the wire.
func newKeyReq(plan wallet.KeyPlan) keyReq {
	return keyReq{ID: plan.ID, Alias: plan.Alias, Pem: plan.Pem}
}

// keyResp is a key record as Fafnir stores it: no private material comes back,
// only the identifier it was filed under and the JWA description of the key.
type keyResp struct {
	ID        string    `json:"id"`
	Alias     string    `json:"alias"`
	Kty       string    `json:"kty"`
	Crv       *string   `json:"crv"`
	CreatedAt time.Time `json:"created_at"`
}

// ToDomain maps the Fafnir record onto the wallet domain entity.
//
// The JWA spellings are checked here, at the boundary: the domain holds them as
// plain strings on the promise that they came off the registry, and this is the
// only place that can keep it.
func (k keyResp) ToDomain() (wallet.Key, error) {
	if k.ID == "" {
		return wallet.Key{}, fmt.Errorf("fafnir: key record carries no id: %w", wallet.ErrNotFound)
	}

	if _, err := jose.ParseKty(k.Kty); err != nil {
		return wallet.Key{}, fmt.Errorf("fafnir: key %q: %w", k.ID, err)
	}

	// RSA and symmetric keys carry no curve, so only a present one is checked.
	if k.Crv != nil && *k.Crv != "" {
		if _, err := jose.ParseCrv(*k.Crv); err != nil {
			return wallet.Key{}, fmt.Errorf("fafnir: key %q: %w", k.ID, err)
		}
	}

	return wallet.Key{
		ID:        k.ID,
		Alias:     k.Alias,
		Kty:       k.Kty,
		Crv:       k.Crv,
		CreatedAt: k.CreatedAt,
	}, nil
}

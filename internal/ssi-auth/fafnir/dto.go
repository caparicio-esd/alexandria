package fafnir

import (
	"encoding/json"
	"fmt"

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

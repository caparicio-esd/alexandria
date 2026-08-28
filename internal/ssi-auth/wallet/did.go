package wallet

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caparicio-esd/alexandria/internal/did"
)

// Did is a Decentralized Identifier owned by this wallet.
//
// The identifier and its document live in the shared did package; what this
// type adds is ownership — the alias the operator gave it, which key signs by
// default, and when it was minted.
type Did struct {
	ID                  did.DID
	Alias               string
	VerificationMethods []did.VerificationMethod
	Services            []did.Service
	DefaultKeyID        string
	CreatedAt           time.Time
}

// Document projects the DID into its resolvable form.
func (d Did) Document() did.Document {
	return did.NewDocument(d.ID, d.VerificationMethods, d.Services)
}

// DidBuilder carries the strategy and method parameters used to mint a DID.
type DidBuilder struct {
	Method did.Method
	// Domain is the DNS name anchoring a did:web. Ignored by other methods.
	Domain string
	// Path is the optional did:web path, as slash-separated segments.
	Path string
}

const maxAliasLen = 64

// Build validates the request and mints the DID. This is the whole minting
// policy: it touches no repository, so it is exhaustively testable on its own.
//
// Identifier derivation and document rules are delegated to the shared did
// package; what stays here is what the wallet decides — how many keys a method
// may bind, how long an alias may be, which algorithms this wallet accepts.
func (b DidBuilder) Build(keys []Key, services []did.Service, now time.Time, alias string) (Did, error) {
	if !b.Method.IsSupported() {
		return Did{}, fmt.Errorf("%w: did method %q", ErrUnsupported, b.Method)
	}

	if len(keys) == 0 {
		return Did{}, invalid("keys_id", "a DID needs at least one verification method")
	}

	if b.Method == did.MethodKey && len(keys) > 1 {
		return Did{}, invalid("keys_id", "did:key is derived from exactly one key")
	}

	if len(alias) > maxAliasLen {
		return Did{}, invalid("alias", fmt.Sprintf("must be at most %d characters", maxAliasLen))
	}

	id, err := b.identifier(keys[0])
	if err != nil {
		return Did{}, err
	}

	vms := make([]did.VerificationMethod, 0, len(keys))
	for _, k := range keys {
		if !k.Alg.IsSupported() {
			return Did{}, invalid("keys_id",
				fmt.Sprintf("key %s uses unsupported algorithm %q", k.ID, k.Alg))
		}

		vms = append(vms, did.VerificationMethod{
			ID:     id.Fragment(k.ID),
			Alg:    k.Alg,
			KeyRef: k.ID,
		})
	}

	if err := translateServiceError(did.ValidateServices(services)); err != nil {
		return Did{}, err
	}

	return Did{
		ID:                  id,
		Alias:               alias,
		VerificationMethods: vms,
		Services:            services,
		DefaultKeyID:        keys[0].ID,
		CreatedAt:           now,
	}, nil
}

// identifier derives the DID for the configured method, translating shared
// kernel errors into this context's validation vocabulary.
func (b DidBuilder) identifier(first Key) (did.DID, error) {
	var (
		id    did.DID
		err   error
		field string
	)

	switch b.Method {
	case did.MethodWeb:
		id, err = did.NewWeb(b.Domain, b.Path)
		field = "builder.domain"
	case did.MethodKey:
		id, err = did.NewKey(first.Thumbprint)
		field = "keys_id"
	default:
		return did.DID{}, fmt.Errorf("%w: did method %q", ErrUnsupported, b.Method)
	}

	switch {
	case errors.Is(err, did.ErrUnsupportedMethod):
		return did.DID{}, fmt.Errorf("%w: did method %q", ErrUnsupported, b.Method)
	case errors.Is(err, did.ErrMalformed):
		return did.DID{}, invalid(field, strings.TrimPrefix(err.Error(), did.ErrMalformed.Error()+": "))
	case err != nil:
		return did.DID{}, fmt.Errorf("deriving the did: %w", err)
	}

	return id, nil
}

// translateServiceError maps a shared kernel service failure onto the field path
// this context exposes.
func translateServiceError(err error) error {
	var svcErr did.ServiceError
	if errors.As(err, &svcErr) {
		return invalid(fmt.Sprintf("service[%d].%s", svcErr.Index, svcErr.Component), svcErr.Reason)
	}

	return err
}

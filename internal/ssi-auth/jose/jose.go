// Package jose is the JOSE boundary of the ssi-auth context.
// ACL layer
//
// Two JOSE stacks live in this binary and neither can be dropped: jwx is what
// this project signs, verifies and thumbprints with, while did-go — whose
// did.Doc the domain uses — exposes keys as kms-go JWKs, which wrap go-jose.
// The conversions between them are collected here so that no other file has to
// hold both vocabularies at once.
//
// Nothing in this package belongs to the domain: wallet states keys in its own
// terms and the adapters translate through here.
package jose

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	didjwk "github.com/trustbloc/kms-go/doc/jose/jwk"
)

var (
	// ErrUnsupportedCrv reports a "crv" this build does not implement. Note
	// that secp256k1 is only registered when compiled with the jwx_es256k
	// build tag — see the Taskfile and Dockerfile.
	ErrUnsupportedCrv = errors.New("unsupported curve")
	// ErrUnsupportedKty reports a "kty" this build does not implement.
	ErrUnsupportedKty = errors.New("unsupported key type")
)

// ParseCrv maps a "crv" spelling onto a curve jwx knows about.
//
// The lookup is exact rather than lenient: "crv" is a registry value, and a
// peer that sends "p256" for "P-256" is wrong in a way worth reporting instead
// of papering over.
func ParseCrv(s string) (jwa.EllipticCurveAlgorithm, error) {
	crv, ok := jwa.LookupEllipticCurveAlgorithm(s)
	if !ok {
		return jwa.EmptyEllipticCurveAlgorithm(), fmt.Errorf("curve %q: %w", s, ErrUnsupportedCrv)
	}

	return crv, nil
}

// ParseKty maps a "kty" spelling onto a key type jwx knows about.
func ParseKty(s string) (jwa.KeyType, error) {
	kty, ok := jwa.LookupKeyType(s)
	if !ok {
		return jwa.InvalidKeyType(), fmt.Errorf("key type %q: %w", s, ErrUnsupportedKty)
	}

	return kty, nil
}

// CurveOf reports the curve a key is on. RSA and symmetric keys carry no
// "crv", so the boolean distinguishes "not an elliptic key" from a failure.
func CurveOf(k jwk.Key) (jwa.EllipticCurveAlgorithm, bool) {
	var crv jwa.EllipticCurveAlgorithm
	if err := k.Get(jwk.ECDSACrvKey, &crv); err != nil {
		return jwa.EmptyEllipticCurveAlgorithm(), false
	}

	return crv, true
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint, base64url-encoded
// without padding — the spelling a "kid" takes.
func Thumbprint(k jwk.Key) (string, error) {
	sum, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("thumbprinting key: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// ToDIDJWK converts a jwx key into the JWK did-go expects when building
// verification methods.
//
// The bridge is the serialised form rather than a field-by-field copy: both
// sides implement RFC 7517, so JSON is the one representation they are
// guaranteed to agree on, and unknown members survive the round trip.
func ToDIDJWK(k jwk.Key) (*didjwk.JWK, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("encoding jwk: %w", err)
	}

	var out didjwk.JWK
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decoding jwk for did-go: %w", err)
	}

	return &out, nil
}

// FromDIDJWK converts a JWK read off a DID Document into a jwx key.
func FromDIDJWK(j *didjwk.JWK) (jwk.Key, error) {
	if j == nil {
		return nil, fmt.Errorf("empty jwk: %w", ErrUnsupportedKty)
	}

	raw, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("encoding jwk from did-go: %w", err)
	}

	key, err := jwk.ParseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding jwk: %w", err)
	}

	return key, nil
}

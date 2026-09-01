package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// verifierBytes is the entropy behind a PKCE verifier. RFC 7636 allows 43 to
// 128 characters; 32 random bytes base64url-encode to 43, which is the floor
// and already far past guessable.
const verifierBytes = 32

// NewVerifier mints a PKCE code verifier.
func NewVerifier() (string, error) {
	return randomString(verifierBytes)
}

// Challenge derives the S256 challenge sent to the authorization endpoint. The
// verifier itself never leaves this node until the code is exchanged, which is
// what binds the two halves of the flow together.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewState mints the anti-forgery value that ties a callback to the login this
// node started.
func NewState() (string, error) {
	return randomString(verifierBytes)
}

// NewNonce mints the value that ties the returned ID token to this same login,
// which is what stops a token minted for another session being replayed here.
func NewNonce() (string, error) {
	return randomString(verifierBytes)
}

// randomString returns n cryptographically random bytes, base64url-encoded
// without padding — the alphabet every one of these values is restricted to.
func randomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("oidc: generating random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

package jose_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/jose"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TestSecp256k1IsRegistered guards the jwx_es256k build tag. jwx compiles
// secp256k1 out unless the tag is set, and it does so silently: without this
// test a build that has lost the tag looks healthy right up to the point where
// it rejects a valid key.
func TestSecp256k1IsRegistered(t *testing.T) {
	t.Parallel()

	if _, err := jose.ParseCrv("secp256k1"); err != nil {
		t.Fatalf("secp256k1 is not registered — build with -tags=jwx_es256k: %v", err)
	}
}

func TestParseCrvRejectsUnknown(t *testing.T) {
	t.Parallel()

	if _, err := jose.ParseCrv("p256"); err == nil {
		t.Fatal("expected the non-registry spelling \"p256\" to be rejected")
	}
}

func TestDIDJWKRoundTrip(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("importing key: %v", err)
	}

	want, err := jose.Thumbprint(key)
	if err != nil {
		t.Fatalf("thumbprinting: %v", err)
	}

	converted, err := jose.ToDIDJWK(key)
	if err != nil {
		t.Fatalf("converting to did-go: %v", err)
	}

	back, err := jose.FromDIDJWK(converted)
	if err != nil {
		t.Fatalf("converting back: %v", err)
	}

	got, err := jose.Thumbprint(back)
	if err != nil {
		t.Fatalf("thumbprinting round-tripped key: %v", err)
	}

	if got != want {
		t.Errorf("thumbprint changed across the did-go boundary: got %q, want %q", got, want)
	}
}

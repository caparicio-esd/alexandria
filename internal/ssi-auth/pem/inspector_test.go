package keys_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	keys "github.com/caparicio-esd/alexandria/internal/ssi-auth/pem"
)

// pkcs8 armours a private key in the one encoding that carries every key type
// this project uses, which is why it is the default the tests reach for.
func pkcs8(t *testing.T, key any) string {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestInspectDescribesTheKey pins the translation: the descriptor speaks JWA,
// in the spellings the registry uses, and nothing else crosses the boundary.
func TestInspectDescribesTheKey(t *testing.T) {
	t.Parallel()

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ed25519 key: %v", err)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a p-256 key: %v", err)
	}

	// 2048 is the smallest size worth exercising; the point of the case is the
	// absent curve, not the modulus.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an rsa key: %v", err)
	}

	cases := map[string]struct {
		material string
		wantKty  string
		wantCrv  string
	}{
		"ed25519 is an octet key pair": {pkcs8(t, ed), "OKP", "Ed25519"},
		"p-256 is an elliptic key":     {pkcs8(t, ec), "EC", "P-256"},
		// RSA keys are not on a curve, and the descriptor says so with an
		// absent Crv rather than an empty string.
		"rsa is on no curve": {pkcs8(t, rsaKey), "RSA", ""},
	}

	inspector := keys.NewInspector()

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := inspector.Inspect(tc.material)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}

			if got.Kty != tc.wantKty {
				t.Errorf("Kty = %q, want %q", got.Kty, tc.wantKty)
			}

			switch {
			case tc.wantCrv == "" && got.Crv != nil:
				t.Errorf("Crv = %q, want it absent", *got.Crv)
			case tc.wantCrv != "" && got.Crv == nil:
				t.Errorf("Crv is absent, want %q", tc.wantCrv)
			case tc.wantCrv != "" && *got.Crv != tc.wantCrv:
				t.Errorf("Crv = %q, want %q", *got.Crv, tc.wantCrv)
			}

			if !got.Private {
				t.Error("Private = false for a private key")
			}

			// The thumbprint becomes a path in the wallet's vault, so its
			// alphabet matters as much as its value: base64url, unpadded.
			if _, err := base64.RawURLEncoding.DecodeString(got.Thumbprint); err != nil {
				t.Errorf("Thumbprint = %q, want unpadded base64url: %v", got.Thumbprint, err)
			}
		})
	}
}

// TestInspectReadsAPublicKey pins that a public key is described rather than
// refused here. Refusing it is the domain's call, and it needs the descriptor
// to make it.
func TestInspectReadsAPublicKey(t *testing.T) {
	t.Parallel()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ed25519 key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("marshalling pkix: %v", err)
	}

	material := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	got, err := keys.NewInspector().Inspect(material)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if got.Private {
		t.Error("Private = true for a public key")
	}
}

// TestInspectRejectionsAreLegible checks the errors as messages, because they
// are rendered verbatim into the response body: they have to say what is wrong
// with the request, and they must not repeat the key back.
func TestInspectRejectionsAreLegible(t *testing.T) {
	t.Parallel()

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ed25519 key: %v", err)
	}

	valid := pkcs8(t, ed)

	encrypted := string(pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("wrapped"),
	}))

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating a 1024-bit rsa key: %v", err)
	}

	cases := map[string]struct {
		material string
		wantWord string
	}{
		"empty":      {"", "pem"},
		"not a pem":  {"just some text", "pem"},
		"two blocks": {valid + valid, "pem"},
		"passphrase": {encrypted, "decrypt"},
		"broken der": {string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})), "cannot read"},
		// A readable file holding an unusable key. The message has to name the
		// size, or the caller has no way to tell what is wrong with a file that
		// opens perfectly well in openssl.
		"weak rsa": {pkcs8(t, weak), "1024"},
	}

	inspector := keys.NewInspector()

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := inspector.Inspect(tc.material)
			if err == nil {
				t.Fatal("Inspect accepted unusable material")
			}

			if !strings.Contains(err.Error(), tc.wantWord) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantWord)
			}

			if tc.material != "" && strings.Contains(err.Error(), tc.material) {
				t.Errorf("the error quotes the material: %q", err)
			}
		})
	}
}

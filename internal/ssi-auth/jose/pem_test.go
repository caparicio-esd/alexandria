package jose_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/jose"
)

// armour wraps DER in the PEM block type that announces it. The tests build
// their material rather than pasting fixtures, so a reader can see which ASN.1
// structure each case is actually exercising.
func armour(t *testing.T, blockType string, der []byte) string {
	t.Helper()

	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func ed25519Pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ed25519 key: %v", err)
	}

	return public, private
}

// TestParsePEMAcceptsTheEncodings walks the block types this build claims to
// read, one per ASN.1 structure behind them.
func TestParsePEMAcceptsTheEncodings(t *testing.T) {
	t.Parallel()

	public, private := ed25519Pair(t)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a p-256 key: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatalf("marshalling sec1: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("marshalling pkix: %v", err)
	}

	cases := map[string]struct {
		material string
		wantKty  string
	}{
		"pkcs#8 private key": {armour(t, "PRIVATE KEY", pkcs8), "OKP"},
		"sec1 private key":   {armour(t, "EC PRIVATE KEY", sec1), "EC"},
		"pkix public key":    {armour(t, "PUBLIC KEY", pkix), "OKP"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := jose.ParsePEM([]byte(tc.material))
			if err != nil {
				t.Fatalf("ParsePEM: %v", err)
			}

			if got := key.KeyType().String(); got != tc.wantKty {
				t.Errorf("kty = %q, want %q", got, tc.wantKty)
			}
		})
	}
}

// TestParsePEMThumbprintIdentifiesThePair pins the property the wallet leans on
// when it names a key after its thumbprint: the value is computed over the
// public half, so a private key and its own public counterpart agree on it.
func TestParsePEMThumbprintIdentifiesThePair(t *testing.T) {
	t.Parallel()

	public, private := ed25519Pair(t)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("marshalling pkix: %v", err)
	}

	privateKey, err := jose.ParsePEM([]byte(armour(t, "PRIVATE KEY", pkcs8)))
	if err != nil {
		t.Fatalf("ParsePEM of the private key: %v", err)
	}

	publicKey, err := jose.ParsePEM([]byte(armour(t, "PUBLIC KEY", pkix)))
	if err != nil {
		t.Fatalf("ParsePEM of the public key: %v", err)
	}

	privateThumb, err := jose.Thumbprint(privateKey)
	if err != nil {
		t.Fatalf("thumbprinting the private key: %v", err)
	}

	publicThumb, err := jose.Thumbprint(publicKey)
	if err != nil {
		t.Fatalf("thumbprinting the public key: %v", err)
	}

	if privateThumb != publicThumb {
		t.Errorf("the pair thumbprinted as %q and %q; the value must name the key, not the encoding",
			privateThumb, publicThumb)
	}
}

// TestParsePEMReportsPrivacy separates the two halves, which is the check the
// domain acts on: a public key parses and cannot sign.
func TestParsePEMReportsPrivacy(t *testing.T) {
	t.Parallel()

	public, private := ed25519Pair(t)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("marshalling pkix: %v", err)
	}

	cases := map[string]struct {
		material string
		want     bool
	}{
		"private": {armour(t, "PRIVATE KEY", pkcs8), true},
		"public":  {armour(t, "PUBLIC KEY", pkix), false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := jose.ParsePEM([]byte(tc.material))
			if err != nil {
				t.Fatalf("ParsePEM: %v", err)
			}

			got, err := jose.IsPrivate(key)
			if err != nil {
				t.Fatalf("IsPrivate: %v", err)
			}

			if got != tc.want {
				t.Errorf("IsPrivate = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParsePEMRejections covers the material that must not travel inwards.
func TestParsePEMRejections(t *testing.T) {
	t.Parallel()

	_, private := ed25519Pair(t)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	valid := armour(t, "PRIVATE KEY", pkcs8)

	cases := map[string]struct {
		material string
		want     error
	}{
		"no armour at all": {
			material: "MC4CAQAwBQYDK2VwBCIEIA==",
			want:     jose.ErrMalformedPEM,
		},
		"armour around rubbish": {
			material: armour(t, "PRIVATE KEY", []byte("not der")),
			want:     jose.ErrMalformedPEM,
		},
		"a block type that holds no key": {
			material: armour(t, "DH PARAMETERS", pkcs8),
			want:     jose.ErrMalformedPEM,
		},
		// Two blocks are ambiguous about which key is being registered, and
		// the library would answer "the first" without saying so.
		"more than one block": {
			material: valid + valid,
			want:     jose.ErrMalformedPEM,
		},
		"pkcs#8 encrypted": {
			material: armour(t, "ENCRYPTED PRIVATE KEY", pkcs8),
			want:     jose.ErrEncryptedPEM,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := jose.ParsePEM([]byte(tc.material))
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want it to match %v", err, tc.want)
			}
		})
	}
}

// TestParsePEMRejectsLegacyEncryption covers the other encryption spelling,
// where the block keeps its ordinary type and a header carries the cipher.
func TestParsePEMRejectsLegacyEncryption(t *testing.T) {
	t.Parallel()

	material := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
		},
		Bytes: []byte("enciphered der"),
	})

	if _, err := jose.ParsePEM(material); !errors.Is(err, jose.ErrEncryptedPEM) {
		t.Errorf("error = %v, want it to match %v", err, jose.ErrEncryptedPEM)
	}
}

// TestParsePEMErrorsHoldNoKeyMaterial is a security property, not a cosmetic
// one: these errors are rendered into HTTP responses and access logs.
func TestParsePEMErrorsHoldNoKeyMaterial(t *testing.T) {
	t.Parallel()

	const secret = "TOPSECRETKEYBYTES"

	material := armour(t, "PRIVATE KEY", []byte(secret))

	_, err := jose.ParsePEM([]byte(material))
	if err == nil {
		t.Fatal("ParsePEM accepted rubbish")
	}

	for _, leak := range []string{secret, material} {
		if got := err.Error(); strings.Contains(got, leak) {
			t.Errorf("the error quotes the input: %q", got)
		}
	}
}

// TestParsePEMRejectsWeakRSA covers the verdict that is not a parse failure: the
// file is perfect and the key inside it is too small to use.
func TestParsePEMRejectsWeakRSA(t *testing.T) {
	t.Parallel()

	// 1024 bits, which is what turns up in key material copied out of old
	// tutorials. Generating it is slow enough to be worth doing once.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating a 1024-bit rsa key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(weak)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	_, err = jose.ParsePEM([]byte(armour(t, "PRIVATE KEY", der)))

	if !errors.Is(err, jose.ErrUnacceptableKey) {
		t.Fatalf("error = %v, want it to match %v", err, jose.ErrUnacceptableKey)
	}

	// The two classes must stay apart. Reporting a readable file as malformed
	// tells the caller to fix something that is not broken.
	if errors.Is(err, jose.ErrMalformedPEM) {
		t.Errorf("a readable file was reported as malformed: %v", err)
	}

	// The size is the one thing the caller needs in order to act.
	if !strings.Contains(err.Error(), "1024") || !strings.Contains(err.Error(), "2048") {
		t.Errorf("error = %q, want it to name the size it got and the size it needs", err)
	}
}

// TestParsePEMAcceptsStrongRSA is the other half: the floor must not reject
// ordinary material.
func TestParsePEMAcceptsStrongRSA(t *testing.T) {
	t.Parallel()

	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a 2048-bit rsa key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(strong)
	if err != nil {
		t.Fatalf("marshalling pkcs#8: %v", err)
	}

	key, err := jose.ParsePEM([]byte(armour(t, "PRIVATE KEY", der)))
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}

	if got := key.KeyType().String(); got != "RSA" {
		t.Errorf("kty = %q, want %q", got, "RSA")
	}
}

// TestKeyErrorsReadAsPredicates pins the shape of the messages rather than their
// wording: they are rendered straight into a response as the reason a field was
// rejected, so they have to read after "the pem you sent" and start lowercase.
func TestKeyErrorsReadAsPredicates(t *testing.T) {
	t.Parallel()

	for _, material := range []string{
		"",
		"not a pem at all",
		armour(t, "PRIVATE KEY", []byte("not der")),
		armour(t, "ENCRYPTED PRIVATE KEY", []byte("wrapped")),
	} {
		_, err := jose.ParsePEM([]byte(material))
		if err == nil {
			t.Fatalf("ParsePEM accepted %q", material)
		}

		reason := err.Error()
		if reason == "" || reason[0] < 'a' || reason[0] > 'z' {
			t.Errorf("reason = %q, want a lowercase predicate", reason)
		}
	}
}

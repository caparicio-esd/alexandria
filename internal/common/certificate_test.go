package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

var testCert = `
-----BEGIN CERTIFICATE-----
MIIBqjCCAU+gAwIBAgIUQ20GkTbbIPEd5hhJolKwrGK48IcwCgYIKoZIzj0EAwIw
KjEaMBgGA1UEAwwRYWxleGFuZHJpYS51cG0uZXMxDDAKBgNVBAoMA1VQTTAeFw0y
NjA4MjcxMjM0NDhaFw0yNzA4MjcxMjM0NDhaMCoxGjAYBgNVBAMMEWFsZXhhbmRy
aWEudXBtLmVzMQwwCgYDVQQKDANVUE0wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARTBR4Y6eKTbdwxnvfMM9HJysHsQQIqgKT9Lw4B9ELym9mRgywR4cLrAizoXm5K
9QRzJoAaCU+YRCLYQHholPrAo1MwUTAdBgNVHQ4EFgQUl+n4LhLl8Rat9evPM/t1
PXWu6AAwHwYDVR0jBBgwFoAUl+n4LhLl8Rat9evPM/t1PXWu6AAwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAk029er8g1GYSw2eQda/Lt7JyRdV1
/c+sgKnykog+QpMCIQC01jSFbAzrsHhJXu5wlhZLo/9i5LDV9EDv8f0ISPQYow==
-----END CERTIFICATE-----
`

func TestTryFromPem(t *testing.T) {
	_, err := TryFromPem(testCert)
	if err != nil {
		t.Fatalf("Pem failed to parse")
	}
	t.Logf("Pem parsed succesfully")
}

func TestDer(t *testing.T) {
	cert, err := TryFromPem(testCert)
	if err != nil {
		t.Fatalf("Pem failed to parse")
	}
	der := cert.Der()
	if len(der) <= 0 {
		t.Fatalf("Der empty")
	}
}

func TestThumbprintSha256(t *testing.T) {
	cert, err := TryFromPem(testCert)
	if err != nil {
		t.Fatalf("Pem failed to parse")
	}
	hash := cert.ThumbprintSha256()
	t.Logf("Computed hash = %s", hash)
}

func TestPublicKey(t *testing.T) {
	cert, err := TryFromPem(testCert)
	if err != nil {
		t.Fatalf("Pem failed to parse")
	}
	pkey, err := cert.PublicKey()
	if err != nil {
		t.Fatalf("Pkey failed to extract")
	}
	t.Logf("Pkey = %s", pkey)
}

// newTestCertPem genera un certificado autofirmado con la ventana de validez
// que se le pida, para poder probar los tres casos de CheckValidity.
func newTestCertPem(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generando clave: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creando certificado: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCheckValidity(t *testing.T) {
	now := time.Now()

	tests := map[string]struct {
		notBefore time.Time
		notAfter  time.Time
		wantErr   bool
	}{
		"vigente":         {now.Add(-time.Hour), now.Add(time.Hour), false},
		"aun no valido":   {now.Add(time.Hour), now.Add(2 * time.Hour), true},
		"caducado":        {now.Add(-2 * time.Hour), now.Add(-time.Hour), true},
		"caduca en 1 seg": {now.Add(-time.Hour), now.Add(time.Second), false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cert, err := TryFromPem(newTestCertPem(t, tc.notBefore, tc.notAfter))
			if err != nil {
				t.Fatalf("TryFromPem: %v", err)
			}

			err = cert.CheckValidity()
			if (err != nil) != tc.wantErr {
				t.Errorf("CheckValidity() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

package common

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

type Certificate struct {
	der []byte
}

func (c *Certificate) isKeySource() {}

func (c *Certificate) Thumbprint() [32]byte {
	return c.ThumbprintSha256()
}

func (c *Certificate) CheckValidity() error {
	certificate, err := x509.ParseCertificate(c.Der())
	if err != nil {
		return err
	}
	now := time.Now()

	if now.Before(certificate.NotBefore) {
		return errors.New("Certificate is not yet valid")
	}
	if now.After(certificate.NotAfter) {
		return errors.New("Certificate has expired")
	}
	return nil
}

func TryFromPem(certPem string) (Certificate, error) {
	normalized := NormalizePem(certPem)
	pem, _ := pem.Decode([]byte(normalized))
	der := pem.Bytes
	return Certificate{
		der: der,
	}, nil
}

func (c *Certificate) Der() []byte {
	return c.der
}

func (c *Certificate) ThumbprintSha256() [32]byte {
	hash := sha256.Sum256(c.Der())
	return hash
}

func (c *Certificate) PublicKey() (any, error) {
	certificate, err := x509.ParseCertificate(c.Der())
	if err != nil {
		return nil, err
	}
	pkey := certificate.PublicKey
	return pkey, nil
}

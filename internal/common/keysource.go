package common

import (
	"fmt"
	"strings"
)

type KeySource interface {
	Thumbprint() string
	CheckValidity() error
	VerifyBytes() error
	isKeySource()
}

func NormalizePem(cert string) string {
	cert = strings.TrimSpace(cert)
	if strings.HasPrefix("-----BEGIN CERTIFICATE-----", cert) {
		return cert
	}
	return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", cert)
}

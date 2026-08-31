package jose

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	// ErrMalformedPEM reports material this build cannot read as a key: no PEM
	// armour, a block type outside the set below, or DER that does not parse.
	ErrMalformedPEM = errors.New("malformed pem")
	// ErrEncryptedPEM reports a passphrase-protected key.
	ErrEncryptedPEM = errors.New("encrypted pem")
	// ErrUnacceptableKey reports material that parses perfectly and holds a key
	// this build refuses to use — too small, or on a curve it was not compiled
	// with. It is a policy verdict, not a parse failure, and the two must stay
	// apart: the caller of a malformed key has a broken file, the caller of an
	// unacceptable one has a working file and the wrong key in it.
	ErrUnacceptableKey = errors.New("unacceptable key")
)

// minRSABits is the smallest RSA modulus this build will hold.
//
// It is jwx's own floor, restated rather than inherited, because the number is
// worth being explicit about: 1024-bit RSA has been below the line since
// NIST SP 800-131A, and turns up constantly in key material copied out of old
// tutorials. Checking it here rather than leaving it to jwx is what lets the
// error say how many bits arrived.
const minRSABits = 2048

// pkcs8EncryptedBlock is the armour PKCS#8 uses for a passphrase-wrapped key
// (RFC 5958 EncryptedPrivateKeyInfo). Nothing in the standard library opens it.
const pkcs8EncryptedBlock = "ENCRYPTED PRIVATE KEY"

// dekInfoHeader marks the older, OpenSSL-specific encryption, where the DER is
// enciphered in place and the block keeps its ordinary type. Go used to open
// these through x509.DecryptPEMBlock, deprecated since 1.16 for using an
// unauthenticated cipher, so they are refused here too.
const dekInfoHeader = "DEK-Info"

// KeyError is a rejection of key material, phrased for whoever supplied it.
//
// Reason is a predicate about the material — it reads after "the pem you sent"
// — and never quotes the material itself, so an adapter can render it into a
// response or a log without editing it. The sentinel behind it says which class
// of rejection this is, for a caller that needs to branch rather than report.
type KeyError struct {
	Reason string
	kind   error
}

// Error implements error.
func (e KeyError) Error() string { return e.Reason }

// Unwrap exposes the sentinel to errors.Is.
func (e KeyError) Unwrap() error { return e.kind }

func malformed(reason string) error {
	return KeyError{Reason: reason, kind: ErrMalformedPEM}
}

// ParsePEM reads PEM-encoded key material into a jwx key.
//
// The block types it accepts are the ones jwx decodes: PKCS#8 ("PRIVATE KEY"),
// PKCS#1 ("RSA PRIVATE KEY", "RSA PUBLIC KEY"), SEC1 ("EC PRIVATE KEY"), PKIX
// ("PUBLIC KEY") and "CERTIFICATE", from which only the subject public key is
// taken — no chain, expiry or usage is checked, because nothing here trusts the
// certificate, it merely carries a key.
//
// Decoding and importing are two steps rather than one call to jwk.ParseKey so
// that the two failures stay distinguishable. jwk.ParseKey collapses them: a
// 1024-bit RSA key and a truncated file come back as the same error, and the
// caller is told their file is broken when it is not.
//
// Errors never quote the input: the argument is private key material, and the
// library's own messages echo what they failed to parse.
func ParsePEM(material []byte) (jwk.Key, error) {
	block, rest := pem.Decode(material)
	if block == nil {
		return nil, malformed("is not pem: no block found")
	}

	if block.Type == pkcs8EncryptedBlock || block.Headers[dekInfoHeader] != "" {
		return nil, KeyError{
			Reason: "is passphrase-protected; decrypt it before registering it",
			kind:   ErrEncryptedPEM,
		}
	}

	// Trailing bytes are refused rather than ignored. A file holding a key and
	// its certificate, or two keys, is ambiguous about which one is being
	// registered, and the decoder would silently answer "the first".
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, malformed("carries more than one pem block; send one key on its own")
	}

	// NewPEMDecoder is jwx's own block-type table, so the set of labels this
	// function accepts stays the set jwx can import. Its documentation says the
	// constructor is planned for deprecation in favour of registered X.509
	// decoders; the replacement is not in v3.2.0 yet.
	raw, _, err := jwk.NewPEMDecoder().Decode(material)
	if err != nil {
		return nil, malformed(fmt.Sprintf("holds a %q block this build cannot read", block.Type))
	}

	if bits, ok := rsaModulusBits(raw); ok && bits < minRSABits {
		return nil, KeyError{
			Reason: fmt.Sprintf("is an rsa key of %d bits; this build requires at least %d", bits, minRSABits),
			kind:   ErrUnacceptableKey,
		}
	}

	key, err := jwk.Import(raw)
	if err != nil {
		// Everything jwx rejects at this point is well-formed and unusable:
		// a curve it was not compiled with, a malformed EC point, an exponent
		// out of range. Its own message names the problem without quoting the
		// key, but it is phrased for a library caller, so it goes to the log
		// through the wrapped error rather than into Reason.
		return nil, KeyError{
			Reason: fmt.Sprintf("holds a %q this build will not use", block.Type),
			kind:   errors.Join(ErrUnacceptableKey, err),
		}
	}

	return key, nil
}

// rsaModulusBits reports the modulus size of an RSA key, and false for anything
// that is not one.
func rsaModulusBits(raw any) (int, bool) {
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		return k.N.BitLen(), true
	case *rsa.PublicKey:
		return k.N.BitLen(), true
	default:
		return 0, false
	}
}

// IsPrivate reports whether the key carries the private half of the pair.
//
// A symmetric key answers false with an error rather than false alone: it is
// not half of anything, and the distinction matters to a caller deciding
// between "send me the private key" and "this kind of key is no use here".
func IsPrivate(k jwk.Key) (bool, error) {
	private, err := jwk.IsPrivateKey(k)
	if err != nil {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedKty, k.KeyType())
	}

	return private, nil
}

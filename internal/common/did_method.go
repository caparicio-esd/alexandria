package common

import (
	"fmt"
	"strings"
)

// DidMethod is the scheme a DID was minted under: the "web" in
// "did:web:alexandria.upm.es".
type DidMethod string

// The methods this build supports. The set is deliberately narrow: did:jwk for
// keys that carry their own identifier, did:web for identifiers resolvable from
// a domain this project controls.
const (
	MethodJwk DidMethod = "jwk"
	MethodWeb DidMethod = "web"
)

// ParseMethod reads a method name, case-insensitively and ignoring surrounding
// space, because it arrives both from callers of this API and from Fafnir, which
// spells it "Jwk". An unknown name is ErrUnsupported rather than invalid input:
// the request is well formed, this build simply does not mint that method.
func ParseMethod(s string) (DidMethod, error) {
	switch DidMethod(strings.ToLower(strings.TrimSpace(s))) {
	case MethodJwk:
		return MethodJwk, nil
	case MethodWeb:
		return MethodWeb, nil
	default:
		return "", fmt.Errorf("did method %q: %w", s, ErrUnsupported)
	}
}

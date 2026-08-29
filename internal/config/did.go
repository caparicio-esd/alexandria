package config

import (
	"fmt"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

// Did selects the identifier scheme this node anchors its identity on.
//
// The Rust original models this as a tagged enum with a nested payload. Go has
// no sum types, and faking one with a custom unmarshaller would cost more than
// it buys: yaml.Node.Decode does not inherit the decoder's strict-field
// setting, so a typo inside this section would stop being an error. The struct
// is therefore flat and dumb, and the pairing rules live in Validate — one
// place, and strict decoding survives.
type Did struct {
	// Method is the DID method, "jwk" or "web".
	Method wallet.Method `mapstructure:"type"`
	// Domain is the authority a did:web resolves from. Unused by did:jwk.
	Domain string `mapstructure:"domain,omitempty"`
	// Path is the optional sub-path a did:web is published under.
	Path string `mapstructure:"path,omitempty"`
	// Port is the optional port a did:web is published on.
	Port string `mapstructure:"port,omitempty"`
}

// Validate implements the section contract, and canonicalises the method
// spelling: peers and operators are inconsistent about casing.
//
// The pointer receiver is what lets it normalise in place; the other sections
// take a value receiver because they only inspect.
func (d *Did) Validate() error {
	method, err := wallet.ParseMethod(string(d.Method))
	if err != nil {
		return fmt.Errorf("%w: ssi_auth.did_config.type: %w", ErrInvalid, err)
	}

	d.Method = method

	switch method {
	case wallet.MethodWeb:
		if d.Domain == "" {
			return invalid("ssi_auth.did_config.domain", "did:web needs a domain to resolve from")
		}
	case wallet.MethodJwk:
		// Rejected rather than ignored: a domain under did:jwk means the
		// operator believes it does something, and it does not.
		if d.Domain != "" || d.Path != "" || d.Port != "" {
			return invalid("ssi_auth.did_config", "did:jwk takes no domain, path or port")
		}
	}

	return nil
}

package did

// Method is the DID method an identifier is minted under.
type Method string

const (
	// MethodKey is did:key — a self-contained identifier derived from one key.
	MethodKey Method = "key"
	// MethodWeb is did:web — an identifier anchored to a DNS domain.
	MethodWeb Method = "web"
)

// IsSupported reports whether this build can parse and mint the method.
func (m Method) IsSupported() bool {
	switch m {
	case MethodKey, MethodWeb:
		return true
	default:
		return false
	}
}

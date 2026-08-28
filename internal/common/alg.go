package common

type Alg string

const (
	AlgRS256 Alg = "RS256"
	AlgRS384 Alg = "RS384"
	AlgRS512 Alg = "RS512"

	AlgPS256 Alg = "PS256"
	AlgPS384 Alg = "PS384"
	AlgPS512 Alg = "PS512"

	AlgEdDSA Alg = "EdDSA"
)

func (a Alg) IsSupported() bool {
	switch a {
	case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512, AlgEdDSA:
		return true
	default:
		return false
	}
}

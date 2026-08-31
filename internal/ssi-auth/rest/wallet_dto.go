package rest

import (
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/trustbloc/did-go/doc/did"
)

// didIDResp answers with the identifier alone, for callers that only need to
// know who this wallet is.
type didIDResp struct {
	Did string `json:"did"`
}

type keyBindingResp struct {
	Fragment string `json:"fragment"`
}

// didResp is the public representation of a wallet DID.
type didResp struct {
	ID                 string           `json:"id"`
	Method             string           `json:"method"`
	Alias              string           `json:"alias,omitempty"`
	Default            bool             `json:"default"`
	Keys               []keyBindingResp `json:"keys"`
	DefaultKeyFragment string           `json:"defaultKeyFragment"`
	// Document is a pointer on purpose: did.Doc declares MarshalJSON on the
	// pointer receiver, so a value field would silently bypass it and emit the
	// Go field names instead of the DID Core ones.
	Document *did.Doc `json:"didDocument"`
}

// newDidResp projects a domain DID onto the wire.
func newDidResp(d wallet.Did) didResp {
	keys := make([]keyBindingResp, 0, len(d.Keys))
	for _, k := range d.Keys {
		keys = append(keys, keyBindingResp{Fragment: k.Fragment})
	}

	return didResp{
		ID:                 d.ID,
		Method:             string(d.Method),
		Alias:              d.Alias,
		Default:            d.Default,
		Keys:               keys,
		DefaultKeyFragment: d.DefaultKey.Fragment,
		Document:           &d.Document,
	}
}

type registerKeyReq struct {
	Pem   string `json:"pem"`
	Alias string `json:"alias,omitempty"`
}

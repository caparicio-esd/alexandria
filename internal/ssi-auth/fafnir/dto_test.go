package fafnir

import (
	"encoding/json"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/trustbloc/did-go/doc/did"
)

const fafnirPayload = `{
    "id": "475e5c94-5bb5-4ce1-8820-9e39dc992213",
    "did": "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ2UFV3bEVyS09BQnR4eW1TNFRGeV9jd2YxczgxR3VNSXNlMlNoS1NkdHgyXzZEamh0X2JrZHVIX3AzY1VraVNzbTdQdFRyZ184MTVRUHNid1dENkJmbWk4OVhvV21ZTUhqSXI2Q1VPdUk2M2JSY09FakVmMnpvWEJockMtR2ViRS1qSk5zNTFQWTZ0MUYwWFIzMTVLczlqLWdHSzZ1MGxTSXMySkdXWFBxVFV2QnlTVzhpeE5MNzBjaHM4OXItZnRvZDRDakg2Mnlod2IzYk1WeWxrTjNIYnZWQVlkRXRpM1FnUXlwRFRNMTViSlVvUy1hZlZRUGRIMlYxbXA3X2FJY2FEUEhTVG1xMUhZQTgxc01lZm9mNTdfRFJWQUxrcXBSTzVEa2hSOTFfeEZqQXRCODEtSnRySHN2c19HZ0lvN24yUnh6MGZScnV4VkNQWlBtVVRDMncifQ",
    "alias": "base",
    "default": true,
    "type": "Jwk",
    "keys": [
        {
            "internal": "private_key.json.example",
            "fragment": "0"
        }
    ],
    "default_key": {
        "internal": "private_key.json.example",
        "fragment": "0"
    },
    "did_document": {
        "@context": [
            "https://www.w3.org/ns/did/v1.1"
        ],
        "id": "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ2UFV3bEVyS09BQnR4eW1TNFRGeV9jd2YxczgxR3VNSXNlMlNoS1NkdHgyXzZEamh0X2JrZHVIX3AzY1VraVNzbTdQdFRyZ184MTVRUHNid1dENkJmbWk4OVhvV21ZTUhqSXI2Q1VPdUk2M2JSY09FakVmMnpvWEJockMtR2ViRS1qSk5zNTFQWTZ0MUYwWFIzMTVLczlqLWdHSzZ1MGxTSXMySkdXWFBxVFV2QnlTVzhpeE5MNzBjaHM4OXItZnRvZDRDakg2Mnlod2IzYk1WeWxrTjNIYnZWQVlkRXRpM1FnUXlwRFRNMTViSlVvUy1hZlZRUGRIMlYxbXA3X2FJY2FEUEhTVG1xMUhZQTgxc01lZm9mNTdfRFJWQUxrcXBSTzVEa2hSOTFfeEZqQXRCODEtSnRySHN2c19HZ0lvN24yUnh6MGZScnV4VkNQWlBtVVRDMncifQ",
        "service": [
            {
                "type": "AuthorizationServer",
                "serviceEndpoint": "http://127.0.0.1:1200/api/v1/gate/access"
            }
        ],
        "verificationMethod": [
            {
                "id": "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ2UFV3bEVyS09BQnR4eW1TNFRGeV9jd2YxczgxR3VNSXNlMlNoS1NkdHgyXzZEamh0X2JrZHVIX3AzY1VraVNzbTdQdFRyZ184MTVRUHNid1dENkJmbWk4OVhvV21ZTUhqSXI2Q1VPdUk2M2JSY09FakVmMnpvWEJockMtR2ViRS1qSk5zNTFQWTZ0MUYwWFIzMTVLczlqLWdHSzZ1MGxTSXMySkdXWFBxVFV2QnlTVzhpeE5MNzBjaHM4OXItZnRvZDRDakg2Mnlod2IzYk1WeWxrTjNIYnZWQVlkRXRpM1FnUXlwRFRNMTViSlVvUy1hZlZRUGRIMlYxbXA3X2FJY2FEUEhTVG1xMUhZQTgxc01lZm9mNTdfRFJWQUxrcXBSTzVEa2hSOTFfeEZqQXRCODEtSnRySHN2c19HZ0lvN24yUnh6MGZScnV4VkNQWlBtVVRDMncifQ#0",
                "controller": "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ2UFV3bEVyS09BQnR4eW1TNFRGeV9jd2YxczgxR3VNSXNlMlNoS1NkdHgyXzZEamh0X2JrZHVIX3AzY1VraVNzbTdQdFRyZ184MTVRUHNid1dENkJmbWk4OVhvV21ZTUhqSXI2Q1VPdUk2M2JSY09FakVmMnpvWEJockMtR2ViRS1qSk5zNTFQWTZ0MUYwWFIzMTVLczlqLWdHSzZ1MGxTSXMySkdXWFBxVFV2QnlTVzhpeE5MNzBjaHM4OXItZnRvZDRDakg2Mnlod2IzYk1WeWxrTjNIYnZWQVlkRXRpM1FnUXlwRFRNMTViSlVvUy1hZlZRUGRIMlYxbXA3X2FJY2FEUEhTVG1xMUhZQTgxc01lZm9mNTdfRFJWQUxrcXBSTzVEa2hSOTFfeEZqQXRCODEtSnRySHN2c19HZ0lvN24yUnh6MGZScnV4VkNQWlBtVVRDMncifQ",
                "type": "JsonWebKey",
                "publicKeyJwk": {
                    "e": "AQAB",
                    "kty": "RSA",
                    "n": "vPUwlErKOABtxymS4TFy_cwf1s81GuMIse2ShKSdtx2_6Djht_bkduH_p3cUkiSsm7PtTrg_815QPsbwWD6Bfmi89XoWmYMHjIr6CUOuI63bRcOEjEf2zoXBhrC-GebE-jJNs51PY6t1F0XR315Ks9j-gGK6u0lSIs2JGWXPqTUvBySW8ixNL70chs89r-ftod4CjH62yhwb3bMVylkN3HbvVAYdEti3QgQypDTM15bJUoS-afVQPdH2V1mp7_aIcaDPHSTmq1HYA81sMefof57_DRVALkqpRO5DkhR91_xFjAtB81-JtrHsvs_GgIo7n2Rxz0fRruxVCPZPmUTC2w"
                }
            }
        ]
    },
    "service": [
        {
            "type": "AuthorizationServer",
            "serviceEndpoint": "http://127.0.0.1:1200/api/v1/gate/access"
        }
    ]
}`

const jwkDid = "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ2UFV3bEVyS09BQnR4eW1TNFRGeV9jd2YxczgxR3VNSXNlMlNoS1NkdHgyXzZEamh0X2JrZHVIX3AzY1VraVNzbTdQdFRyZ184MTVRUHNid1dENkJmbWk4OVhvV21ZTUhqSXI2Q1VPdUk2M2JSY09FakVmMnpvWEJockMtR2ViRS1qSk5zNTFQWTZ0MUYwWFIzMTVLczlqLWdHSzZ1MGxTSXMySkdXWFBxVFV2QnlTVzhpeE5MNzBjaHM4OXItZnRvZDRDakg2Mnlod2IzYk1WeWxrTjNIYnZWQVlkRXRpM1FnUXlwRFRNMTViSlVvUy1hZlZRUGRIMlYxbXA3X2FJY2FEUEhTVG1xMUhZQTgxc01lZm9mNTdfRFJWQUxrcXBSTzVEa2hSOTFfeEZqQXRCODEtSnRySHN2c19HZ0lvN24yUnh6MGZScnV4VkNQWlBtVVRDMncifQ"

// TestDidRespDecodes pins the wire contract: a real Fafnir record must decode
// without the embedded document being validated, so a non-conformant document
// never costs us the rest of the record.
func TestDidRespDecodes(t *testing.T) {
	t.Parallel()

	var got didResp
	if err := json.Unmarshal([]byte(fafnirPayload), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != "475e5c94-5bb5-4ce1-8820-9e39dc992213" {
		t.Errorf("ID = %q", got.ID)
	}

	if got.Did != jwkDid {
		t.Errorf("Did = %q", got.Did)
	}

	if !got.Default || got.Type != "Jwk" || got.Alias != "base" {
		t.Errorf("flags = %v %q %q", got.Default, got.Type, got.Alias)
	}

	if len(got.Keys) != 1 || got.Keys[0].Internal != "private_key.json.example" || got.Keys[0].Fragment != "0" {
		t.Errorf("Keys = %+v", got.Keys)
	}

	if got.DefaultKey != (keyRef{Internal: "private_key.json.example", Fragment: "0"}) {
		t.Errorf("DefaultKey = %+v", got.DefaultKey)
	}
}

// TestDidRespToDomain covers the anti-corruption boundary: Fafnir's spellings
// and its non-conformant document must be repaired here, not in the domain.
func TestDidRespToDomain(t *testing.T) {
	t.Parallel()

	var got didResp
	if err := json.Unmarshal([]byte(fafnirPayload), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	domain, err := got.ToDomain()
	if err != nil {
		t.Fatalf("ToDomain(): %v", err)
	}

	if domain.Method != wallet.MethodJwk {
		t.Errorf("Method = %q, want %q", domain.Method, wallet.MethodJwk)
	}

	if domain.Alias != "base" || !domain.Default {
		t.Errorf("alias/default = %q / %v", domain.Alias, domain.Default)
	}

	if domain.DefaultKey.KeyID != "private_key.json.example" || domain.DefaultKey.Fragment != "0" {
		t.Errorf("DefaultKey = %+v", domain.DefaultKey)
	}

	doc := domain.Document

	if doc.ID != jwkDid {
		t.Errorf("doc.ID = %q", doc.ID)
	}

	if n := len(doc.VerificationMethod); n != 1 {
		t.Fatalf("verification methods = %d, want 1", n)
	}

	if got, want := doc.VerificationMethod[0].ID, jwkDid+"#0"; got != want {
		t.Errorf("vm id = %q, want %q", got, want)
	}

	if n := len(doc.Service); n != 1 {
		t.Fatalf("services = %d, want 1", n)
	}

	// The id was absent on the wire; normalisation injects it.
	if got, want := doc.Service[0].ID, jwkDid+"#service-0"; got != want {
		t.Errorf("service id = %q, want %q", got, want)
	}

	if doc.Service[0].Type != "AuthorizationServer" {
		t.Errorf("service type = %q", doc.Service[0].Type)
	}
}

// TestNormalizeDidDocumentIsNeeded fails the day Fafnir starts emitting
// conformant documents, which is the signal to delete normalize.go.
func TestNormalizeDidDocumentIsNeeded(t *testing.T) {
	t.Parallel()

	var got didResp
	if err := json.Unmarshal([]byte(fafnirPayload), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, err := did.ParseDocument(got.DidDocument); err == nil {
		t.Fatal("the raw Fafnir document now validates: drop normalize.go and this test")
	}
}

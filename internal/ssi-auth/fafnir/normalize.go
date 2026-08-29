package fafnir

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TEMPORARY: Fafnir currently emits DID Documents that do not validate against
// DID Core, and this file patches them on the way in.
//
// Both deviations are upstream bugs and should be fixed in Fafnir itself:
//
//   - "@context" is emitted as .../did/v1.1. The DID Core schema this project
//     validates against only accepts .../did/v1.
//   - "service" entries omit "id", which DID Core requires. A conforming
//     producer must also keep those ids unique within the document.
//
// Delete this file once Fafnir emits conformant documents.

const (
	contextV11 = "https://www.w3.org/ns/did/v1.1"
	contextV1  = "https://www.w3.org/ns/did/v1"
)

// normalizeDidDocument rewrites the known Fafnir deviations so the document
// validates. It works on the raw JSON rather than a typed struct so that fields
// it does not know about survive untouched.
func normalizeDidDocument(raw []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("normalising did document: %w", err)
	}

	normalizeContext(doc)
	normalizeServiceIDs(doc)

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("re-encoding did document: %w", err)
	}

	return out, nil
}

// normalizeContext downgrades the DID v1.1 context to v1, in either the string
// or the array form the specification allows.
func normalizeContext(doc map[string]any) {
	switch ctx := doc["@context"].(type) {
	case string:
		if ctx == contextV11 {
			doc["@context"] = contextV1
		}
	case []any:
		for i, entry := range ctx {
			if s, ok := entry.(string); ok && s == contextV11 {
				ctx[i] = contextV1
			}
		}
	}
}

// normalizeServiceIDs fills in the id of every service entry that lacks one,
// using a fragment on the document subject. The "service-" prefix keeps these
// ids from colliding with the verification method fragments, which Fafnir
// numbers plainly ("#0", "#1").
func normalizeServiceIDs(doc map[string]any) {
	services, ok := doc["service"].([]any)
	if !ok {
		return
	}

	subject, _ := doc["id"].(string)

	for i, entry := range services {
		service, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		if id, ok := service["id"].(string); ok && strings.TrimSpace(id) != "" {
			continue
		}

		service["id"] = fmt.Sprintf("%s#service-%d", subject, i)
	}
}

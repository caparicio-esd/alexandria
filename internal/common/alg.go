// Package common holds helpers shared across the application.
package common

// Alg names a signature algorithm, in JWA terms — "ES256", "EdDSA" and the
// like.
//
// PLACEHOLDER: this is the minimum that internal/ssi-auth/wallet needs to
// compile. The package it belongs to was removed and is being rebuilt; fold
// this type into that work, with the catalogue of values it should carry.
type Alg string

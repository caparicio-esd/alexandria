// Package identity carries the authenticated caller across the process.
//
// It holds no policy and no transport: a driving adapter puts a Principal on
// the request context and anything downstream — another bounded context's
// handler, a use case, an audit record — reads it back without importing the
// authentication machinery, or knowing that Zitadel is what produced it. That
// is the whole point of the package being this small.
package identity

import (
	"context"
	"strings"
	"time"
)

// principalKey is the context key carrying the authenticated caller. Unexported
// struct type, so it cannot collide with a key set anywhere else.
type principalKey struct{}

// Principal is the caller a token resolved to.
//
// The claims are copied out into named fields rather than left as a bag,
// because everything downstream wants the same four things; the bag stays
// alongside for the deployment-specific claim nobody here can name.
type Principal struct {
	// Subject is the provider's stable identifier for the caller, "sub".
	Subject string
	// Username is the login name, where the provider sent one.
	Username string
	// Email is the verified address, where the token carries one.
	Email string
	// Name is the display name.
	Name string
	// Organization is the tenant the caller belongs to, for a provider that is
	// multi-tenant — Zitadel puts its organization id in a claim of its own.
	Organization string
	// Scopes are the OAuth scopes the token was granted.
	Scopes []string
	// Roles are the application roles, flattened out of whatever shape the
	// provider encodes them in.
	Roles []string
	// Machine reports a service account rather than a human: a token minted by
	// the client credentials grant, which carries no user behind it.
	Machine bool
	// ExpiresAt is when the token stops being valid, so a handler can decide
	// whether a long operation will outlive its own authorization.
	ExpiresAt time.Time
	// Claims is the raw claim set, for the deployment-specific value this
	// struct cannot anticipate.
	Claims map[string]any
}

// HasScope reports whether the token was granted a scope.
func (p *Principal) HasScope(scope string) bool { return contains(p.Scopes, scope) }

// HasRole reports whether the caller holds a role.
func (p *Principal) HasRole(role string) bool { return contains(p.Roles, role) }

// HasEveryRole reports whether the caller holds all of them, which is how a
// gate with more than one requirement is spelled. No roles required is no bar
// to clear, so it answers true.
func (p *Principal) HasEveryRole(roles []string) bool {
	for _, role := range roles {
		if !p.HasRole(role) {
			return false
		}
	}

	return true
}

// contains is a case-sensitive membership test: scopes and roles are
// identifiers, and folding case would let "Admin" pass a check written for
// "admin".
func contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}

	return false
}

// SplitScopes parses the space-delimited "scope" claim.
func SplitScopes(raw string) []string {
	return strings.Fields(raw)
}

// WithPrincipal returns a context carrying the authenticated caller.
func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

// FromContext recovers the caller, or nil when the request was never
// authenticated — which is the case on a public route, and never on a
// protected one.
func FromContext(ctx context.Context) *Principal {
	principal, _ := ctx.Value(principalKey{}).(*Principal)

	return principal
}

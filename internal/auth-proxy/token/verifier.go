// Package token turns a bearer credential into the caller it stands for.
//
// The fast path is local: an access token that is a JWS is verified against the
// provider's published signing keys, with no round trip, which is what makes
// protecting every route affordable. The slow path is introspection, for a
// provider configured to issue opaque tokens — Zitadel's default for an
// application that has not asked for JWTs.
package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/identity"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/oidc"
	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	// ErrUnauthenticated reports a credential that does not resolve to a
	// caller: expired, signed by a key this issuer does not publish, meant for
	// somebody else, or revoked. They are one error on purpose — the caller
	// gets 401 for all of them, and the reason goes to the log, not the body.
	ErrUnauthenticated = errors.New("not authenticated")
	// ErrNotReady reports that the provider's keys have not been read yet, so
	// nothing can be verified. It is an outage, not a rejection, and the
	// difference is a 503 rather than a 401.
	ErrNotReady = errors.New("verifier not ready")
)

// Zitadel's claim names. The role claim is configurable — a project can be set
// to emit its roles under a project-scoped URN instead — so it arrives as
// configuration; the rest are fixed by the product.
const (
	claimUsername = "preferred_username"
	claimEmail    = "email"
	claimName     = "name"
	claimOrgID    = "urn:zitadel:iam:user:resourceowner:id"
	claimScope    = "scope"
	claimAMR      = "amr"
	// rolePrefix and roleSuffix bracket the project-scoped spelling,
	// urn:zitadel:iam:org:project:<id>:roles, which a project emits when it is
	// configured to assert roles per audience rather than globally.
	rolePrefix = "urn:zitadel:iam:org:project:"
	roleSuffix = ":roles"
)

// Verifier resolves credentials against one provider.
type Verifier struct {
	client     *oidc.Client
	logger     *slog.Logger
	issuer     string
	audiences  []string
	mode       config.IntrospectMode
	rolesClaim string
	refresh    time.Duration

	// keys is the auto-refreshing view of the provider's JWKS. It is nil until
	// Bind runs, which is after discovery, which is after the provider is up —
	// so every read goes through the mutex.
	mu    sync.RWMutex
	cache *jwk.Cache
	keys  jwk.Set
}

// New builds a verifier. It contacts nothing: the keys are bound once the
// discovery document says where they live.
func New(client *oidc.Client, cfg config.Auth, logger *slog.Logger) *Verifier {
	if logger == nil {
		logger = slog.Default()
	}

	return &Verifier{ //nolint:exhaustruct // the key set is bound later, by Bind
		client:     client,
		logger:     logger,
		issuer:     strings.TrimSuffix(cfg.Issuer, "/"),
		audiences:  cfg.Audiences,
		mode:       cfg.Introspect,
		rolesClaim: cfg.RolesClaim,
		refresh:    cfg.JWKSRefresh,
	}
}

// Bind starts following the provider's signing keys.
//
// The cache re-fetches on its own schedule and honours the JWKS endpoint's
// cache headers, so a rotation is picked up without a restart and without a
// fetch per request.
func (v *Verifier) Bind(ctx context.Context, jwksURI string) error {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return fmt.Errorf("token: building the key cache: %w", err)
	}

	if err := cache.Register(ctx, jwksURI, jwk.WithMinInterval(v.refresh)); err != nil {
		return fmt.Errorf("token: registering %q: %w", jwksURI, err)
	}

	keys, err := cache.CachedSet(jwksURI)
	if err != nil {
		return fmt.Errorf("token: reading the key set at %q: %w", jwksURI, err)
	}

	v.mu.Lock()
	previous := v.cache
	v.cache, v.keys = cache, keys
	v.mu.Unlock()

	// A rebind — the provider was reconfigured and discovery ran again — must
	// not leave the previous cache's goroutines running.
	if previous != nil {
		_ = previous.Shutdown(ctx)
	}

	return nil
}

// Ready reports whether anything can be verified yet.
func (v *Verifier) Ready() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.keys != nil
}

// Close stops the key cache's goroutines.
func (v *Verifier) Close(ctx context.Context) error {
	v.mu.Lock()
	cache := v.cache
	v.cache, v.keys = nil, nil
	v.mu.Unlock()

	if cache == nil {
		return nil
	}

	if err := cache.Shutdown(ctx); err != nil {
		return fmt.Errorf("token: shutting down the key cache: %w", err)
	}

	return nil
}

// Verify resolves a raw access token into the caller it stands for.
func (v *Verifier) Verify(ctx context.Context, raw string) (*identity.Principal, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("token: empty credential: %w", ErrUnauthenticated)
	}

	if v.mode == config.IntrospectAlways {
		return v.introspect(ctx, raw)
	}

	principal, err := v.verifyJWT(ctx, raw)
	if err == nil {
		return principal, nil
	}

	// Only a token that is not a JWS at all is worth a round trip. One that is
	// a JWS and failed to verify is a rejection, and asking the provider to
	// confirm it would turn every bad token into an outbound request — which is
	// how a bad client becomes a denial of service against the provider.
	if !errors.Is(err, errNotAJWS) || v.mode != config.IntrospectFallback {
		return nil, err
	}

	return v.introspect(ctx, raw)
}

// VerifyID checks an ID token and the nonce it must carry.
//
// The access token says the provider authenticated somebody; only the nonce
// says it was this login, on this browser, in the session that started it. A
// callback that skips it accepts an ID token minted for another session and
// replayed here, which is the attack the parameter exists for.
//
// The audience of an ID token is the client, always — unlike the access token,
// whose audience is whatever the deployment configured.
func (v *Verifier) VerifyID(ctx context.Context, raw, nonce, clientID string) error {
	v.mu.RLock()
	keys := v.keys
	v.mu.RUnlock()

	if keys == nil {
		return ErrNotReady
	}

	parsed, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(keys),
		jwt.WithValidate(true),
		jwt.WithContext(ctx),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(clientID),
	)
	if err != nil {
		return fmt.Errorf("token: id token: %w: %w", ErrUnauthenticated, err)
	}

	var claimed string
	if err := parsed.Get("nonce", &claimed); err != nil {
		return fmt.Errorf("token: the id token carries no nonce: %w", ErrUnauthenticated)
	}

	// Constant time, because this is a secret being compared against attacker-
	// supplied input, and the cost of doing it right is a function call.
	if subtle.ConstantTimeCompare([]byte(claimed), []byte(nonce)) != 1 {
		return fmt.Errorf("token: the id token answers a different login: %w", ErrUnauthenticated)
	}

	return nil
}

// errNotAJWS separates "this is an opaque token" from "this token is bad", so
// only the first falls through to introspection.
var errNotAJWS = errors.New("not a signed token")

// verifyJWT is the local path: signature, issuer, audience and expiry, all
// against the cached key set.
func (v *Verifier) verifyJWT(ctx context.Context, raw string) (*identity.Principal, error) {
	// Three dot-separated segments is what a JWS compact serialization is; an
	// opaque Zitadel token is a single opaque string.
	if strings.Count(raw, ".") != 2 {
		return nil, fmt.Errorf("token: %w: %w", errNotAJWS, ErrUnauthenticated)
	}

	v.mu.RLock()
	keys := v.keys
	v.mu.RUnlock()

	if keys == nil {
		return nil, ErrNotReady
	}

	options := []jwt.ParseOption{
		jwt.WithKeySet(keys),
		jwt.WithValidate(true),
		jwt.WithContext(ctx),
		jwt.WithIssuer(v.issuer),
	}

	// Every configured audience is required, not just one of them: the list is
	// what this node answers for, and a token minted for a different
	// application of the same provider must not open this API.
	for _, audience := range v.audiences {
		options = append(options, jwt.WithAudience(audience))
	}

	parsed, err := jwt.Parse([]byte(raw), options...)
	if err != nil {
		return nil, fmt.Errorf("token: %w: %w", ErrUnauthenticated, err)
	}

	return v.principalFromJWT(parsed), nil
}

// principalFromJWT projects a verified token onto the process's own vocabulary.
func (v *Verifier) principalFromJWT(parsed jwt.Token) *identity.Principal {
	claims := make(map[string]any, len(parsed.Keys()))

	for _, name := range parsed.Keys() {
		var value any
		if err := parsed.Get(name, &value); err == nil {
			claims[name] = value
		}
	}

	subject, _ := parsed.Subject()
	expiry, _ := parsed.Expiration()

	return v.principalFromClaims(subject, claims, expiry)
}

// introspect is the remote path, for an opaque token.
func (v *Verifier) introspect(ctx context.Context, raw string) (*identity.Principal, error) {
	result, err := v.client.Introspect(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("token: introspecting: %w", err)
	}

	if !result.Active {
		return nil, fmt.Errorf("token: the provider reports the token inactive: %w", ErrUnauthenticated)
	}

	if result.Issuer != "" && result.Issuer != v.issuer {
		return nil, fmt.Errorf("token: issued by %q, not %q: %w", result.Issuer, v.issuer, ErrUnauthenticated)
	}

	if !audienceAccepted(result.Audience, v.audiences) {
		return nil, fmt.Errorf("token: not addressed to this node: %w", ErrUnauthenticated)
	}

	var expiry time.Time
	if result.Expires > 0 {
		expiry = time.Unix(result.Expires, 0)
	}

	return v.principalFromClaims(result.Subject, result.Claims, expiry), nil
}

// audienceAccepted checks the introspection response's "aud", which the
// specification allows to be a string or an array. jwt.Parse does this for the
// local path; introspection has no such helper.
func audienceAccepted(claim any, required []string) bool {
	if len(required) == 0 {
		return true
	}

	present := map[string]bool{}

	switch value := claim.(type) {
	case string:
		present[value] = true
	case []string:
		for _, entry := range value {
			present[entry] = true
		}
	case []any:
		for _, entry := range value {
			if text, ok := entry.(string); ok {
				present[text] = true
			}
		}
	}

	for _, audience := range required {
		if !present[audience] {
			return false
		}
	}

	return true
}

// principalFromClaims is the one place claims become a Principal, so the two
// paths cannot disagree about what a caller is.
func (v *Verifier) principalFromClaims(subject string, claims map[string]any, expiry time.Time) *identity.Principal {
	principal := &identity.Principal{ //nolint:exhaustruct // filled in below
		Subject:   subject,
		Claims:    claims,
		ExpiresAt: expiry,
	}

	principal.Username, _ = claims[claimUsername].(string)
	principal.Email, _ = claims[claimEmail].(string)
	principal.Name, _ = claims[claimName].(string)
	principal.Organization, _ = claims[claimOrgID].(string)

	if scope, ok := claims[claimScope].(string); ok {
		principal.Scopes = identity.SplitScopes(scope)
	}

	principal.Roles = v.rolesFrom(claims)

	// A heuristic, and named as one: the client credentials grant produces a
	// token with no human behind it, and what distinguishes it is the absence
	// of an authentication method reference and of a login name. Getting it
	// wrong costs nothing structural — it is reported, never enforced on.
	_, hasAMR := claims[claimAMR]
	principal.Machine = !hasAMR && principal.Username == "" && principal.Email == ""

	return principal
}

// rolesFrom flattens whatever shape the provider encoded roles in.
//
// Zitadel writes a map of role name to a map of organization id to domain,
// which is more structure than an authorization check wants; the org is already
// on the principal, so the names are what comes out. A provider that writes a
// plain array is handled too, because one will.
func (v *Verifier) rolesFrom(claims map[string]any) []string {
	var roles []string

	collect := func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for role := range typed {
				roles = append(roles, role)
			}
		case []any:
			for _, entry := range typed {
				if role, ok := entry.(string); ok {
					roles = append(roles, role)
				}
			}
		case []string:
			roles = append(roles, typed...)
		}
	}

	if v.rolesClaim != "" {
		collect(claims[v.rolesClaim])
	}

	// The project-scoped spelling, whose claim name carries a project id this
	// package cannot know in advance.
	for name, value := range claims {
		if name != v.rolesClaim && strings.HasPrefix(name, rolePrefix) && strings.HasSuffix(name, roleSuffix) {
			collect(value)
		}
	}

	return roles
}

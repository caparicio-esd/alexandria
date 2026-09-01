package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SessionKeyBytes is the length of the key that seals the session cookie:
// AES-256-GCM, so nothing shorter is accepted.
const SessionKeyBytes = 32

// IntrospectMode says how an opaque access token — one that is not a JWS, which
// is what Zitadel issues unless the application is configured otherwise — is
// resolved.
type IntrospectMode string

const (
	// IntrospectNever refuses anything that does not verify locally as a JWT.
	IntrospectNever IntrospectMode = "never"
	// IntrospectFallback verifies locally first and calls the introspection
	// endpoint only for a token that is not a JWS. It is the default: it costs
	// nothing on the JWT path and still accepts an opaque token.
	IntrospectFallback IntrospectMode = "fallback"
	// IntrospectAlways sends every token to the introspection endpoint, which
	// is the only way to see a revocation the moment it happens — at the price
	// of one upstream call per request.
	IntrospectAlways IntrospectMode = "always"
)

// Auth is the authentication boundary: the OpenID Provider this node trusts —
// Zitadel — and how the proxy in front of it behaves.
//
// The node is a confidential client. The browser never receives a token and
// never talks to the provider directly: it follows redirects through
// /api/v1/auth and carries a sealed, HttpOnly session cookie. That is what
// makes the client secret usable at all, and it keeps the provider's hostname
// out of the frontend's configuration.
type Auth struct {
	// Enabled switches the whole context on. Off, no route is protected and no
	// provider is contacted — which is a development setting, not a deployment
	// one.
	Enabled bool `mapstructure:"enabled"`
	// Issuer is the provider's issuer URL, the one its discovery document
	// echoes back. Every token is checked against it.
	Issuer string `mapstructure:"issuer"`
	// InternalIssuer is where this process reaches the provider when that is
	// not where the browser reaches it — a container name against a published
	// host. Empty means they are the same. Discovery and the token calls use
	// it; the issuer that tokens are validated against is always Issuer.
	InternalIssuer string `mapstructure:"internal_issuer,omitempty"`
	// ClientID is this node's registered application.
	ClientID string `mapstructure:"client_id"`
	// ClientSecret authenticates it at the token endpoint. Absent for a public
	// client, where PKCE alone carries the exchange.
	ClientSecret string `mapstructure:"client_secret,omitempty"`
	// Audiences are the "aud" values an access token may carry. Empty accepts
	// any audience, which is only safe when this node is the sole relying
	// party of the provider.
	Audiences []string `mapstructure:"audiences,omitempty"`
	// Scopes are requested at the authorization endpoint. offline_access is
	// what earns a refresh token, without which every session dies with the
	// first access token.
	Scopes []string `mapstructure:"scopes"`
	// RedirectURL is this node's own callback, as the provider must have it
	// registered.
	RedirectURL string `mapstructure:"redirect_url"`
	// AppURL is where the browser is sent once a login completes, when the
	// caller named no destination of its own.
	AppURL string `mapstructure:"app_url"`
	// PostLogoutURL is where the provider returns the browser after ending the
	// session. Empty falls back to AppURL.
	PostLogoutURL string `mapstructure:"post_logout_url,omitempty"`
	// Introspect selects how an opaque token is resolved.
	Introspect IntrospectMode `mapstructure:"introspect"`
	// RolesClaim is the claim the provider puts project roles in. Zitadel's
	// default is a URN, and it is configurable per project, so it is not
	// hard-coded.
	RolesClaim string `mapstructure:"roles_claim"`
	// RequiredRoles gate the whole API: a principal without every one of them
	// is refused before any handler runs. Empty gates nothing, and
	// authentication alone is the bar.
	RequiredRoles []string `mapstructure:"required_roles,omitempty"`
	// JWKSRefresh is how often the signing keys are re-fetched.
	JWKSRefresh time.Duration `mapstructure:"jwks_refresh"`
	// HTTPTimeout bounds every call to the provider.
	HTTPTimeout time.Duration `mapstructure:"http_timeout"`
	// StartupDiscoveryTimeout is how long startup blocks on the discovery
	// document before continuing in the background, exactly as the wallet
	// handshake does.
	StartupDiscoveryTimeout time.Duration `mapstructure:"startup_discovery_timeout"`
	// Session describes the cookie the proxy hands the browser.
	Session SessionCookie `mapstructure:"session"`
}

// SessionCookie is the sealed cookie the tokens live in.
type SessionCookie struct {
	// Name is the cookie name.
	Name string `mapstructure:"name"`
	// Domain scopes the cookie. Empty is host-only, which is what a single
	// origin wants.
	Domain string `mapstructure:"domain,omitempty"`
	// Path scopes the cookie. It defaults to "/" so a session survives a
	// navigation outside the API prefix.
	Path string `mapstructure:"path"`
	// Secure marks the cookie HTTPS-only. It is mandatory in production and
	// unusable on a plain-HTTP workstation, which is why it is a setting.
	Secure bool `mapstructure:"secure"`
	// SameSite is "lax", "strict" or "none". "none" requires Secure.
	SameSite string `mapstructure:"same_site"`
	// TTL is how long a session lives, whatever the access token's own expiry:
	// the proxy refreshes underneath it.
	TTL time.Duration `mapstructure:"ttl"`
	// Key seals the cookie: 32 bytes, hex or base64. Empty is tolerated
	// outside production, where a random one is minted per process — sessions
	// then die with a restart, which on a workstation is a fair trade for not
	// committing a key.
	Key string `mapstructure:"key,omitempty"`
}

// Validate implements the section contract. isProd tightens the rules that are
// only relaxed for a workstation.
func (a *Auth) Validate(isProd bool) error {
	if !a.Enabled {
		return nil
	}

	a.Introspect = IntrospectMode(strings.ToLower(strings.TrimSpace(string(a.Introspect))))

	errs := []error{
		a.validateEndpoints(),
		a.validateMode(),
		a.Session.validate(isProd),
	}

	if a.ClientID == "" {
		errs = append(errs, invalid("auth_config.client_id", "must be set"))
	}

	if isProd && a.ClientSecret == "" {
		errs = append(errs, invalid("auth_config.client_secret",
			"a confidential client needs a secret outside development"))
	}

	if a.JWKSRefresh <= 0 {
		errs = append(errs, invalid("auth_config.jwks_refresh", "must be positive"))
	}

	if a.HTTPTimeout <= 0 {
		errs = append(errs, invalid("auth_config.http_timeout", "must be positive"))
	}

	if a.StartupDiscoveryTimeout < 0 {
		errs = append(errs, invalid("auth_config.startup_discovery_timeout", "must not be negative"))
	}

	return errors.Join(errs...)
}

// validateEndpoints checks the three URLs the flow cannot be assembled without.
func (a *Auth) validateEndpoints() error {
	var errs []error

	for field, raw := range map[string]string{
		"auth_config.issuer":          a.Issuer,
		"auth_config.redirect_url":    a.RedirectURL,
		"auth_config.app_url":         a.AppURL,
		"auth_config.internal_issuer": a.InternalIssuer,
	} {
		if raw == "" {
			// Only the issuer and the redirect are load-bearing; the rest have
			// sensible fallbacks and are checked where they are used.
			if field == "auth_config.issuer" || field == "auth_config.redirect_url" {
				errs = append(errs, invalid(field, "must be set"))
			}

			continue
		}

		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			errs = append(errs, invalid(field, fmt.Sprintf("%q must be an absolute url", raw)))
		}
	}

	return errors.Join(errs...)
}

// validateMode checks the introspection selector.
func (a *Auth) validateMode() error {
	switch a.Introspect {
	case IntrospectNever, IntrospectFallback, IntrospectAlways:
		return nil
	default:
		return invalid("auth_config.introspect",
			fmt.Sprintf("unknown mode %q: never, fallback or always", a.Introspect))
	}
}

// validate implements the section contract for the cookie block.
func (s *SessionCookie) validate(isProd bool) error {
	var errs []error

	s.SameSite = strings.ToLower(strings.TrimSpace(s.SameSite))

	switch s.SameSite {
	case "lax", "strict":
	case "none":
		if !s.Secure {
			errs = append(errs, invalid("auth_config.session.same_site",
				`"none" is only sent over https, so secure must be true`))
		}
	default:
		errs = append(errs, invalid("auth_config.session.same_site",
			fmt.Sprintf("unknown policy %q: lax, strict or none", s.SameSite)))
	}

	if s.Name == "" {
		errs = append(errs, invalid("auth_config.session.name", "must be set"))
	}

	if s.TTL <= 0 {
		errs = append(errs, invalid("auth_config.session.ttl", "must be positive"))
	}

	if isProd && !s.Secure {
		errs = append(errs, invalid("auth_config.session.secure",
			"a session cookie must not travel in clear in production"))
	}

	if s.Key == "" {
		if isProd {
			errs = append(errs, invalid("auth_config.session.key",
				"must be set in production, or every restart invalidates every session"))
		}
	} else if _, err := s.SealingKey(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// SealingKey decodes the configured key. Hex and base64 are both accepted
// because the two commands an operator reaches for — openssl rand -hex 32 and
// openssl rand -base64 32 — print one each, and rejecting either would be a
// papercut with no upside.
func (s SessionCookie) SealingKey() ([]byte, error) {
	if s.Key == "" {
		return nil, invalid("auth_config.session.key", "not set")
	}

	if raw, err := hex.DecodeString(s.Key); err == nil && len(raw) == SessionKeyBytes {
		return raw, nil
	}

	raw, err := base64.StdEncoding.DecodeString(s.Key)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(s.Key)
	}

	if err != nil || len(raw) != SessionKeyBytes {
		return nil, invalid("auth_config.session.key",
			fmt.Sprintf("must decode to %d bytes of hex or base64", SessionKeyBytes))
	}

	return raw, nil
}

// SameSitePolicy renders the configured policy in the vocabulary net/http
// speaks.
func (s SessionCookie) SameSitePolicy() http.SameSite {
	switch s.SameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// CookiePath is the path the cookie is scoped to, defaulting to the whole
// origin.
func (s SessionCookie) CookiePath() string {
	if s.Path == "" {
		return "/"
	}

	return s.Path
}

// ProviderURL is where this process reaches the provider, which is the internal
// address when the deployment publishes a different one.
func (a Auth) ProviderURL() string {
	if a.InternalIssuer != "" {
		return strings.TrimSuffix(a.InternalIssuer, "/")
	}

	return strings.TrimSuffix(a.Issuer, "/")
}

// LandingURL is where the browser is sent when a flow completes without naming
// a destination.
func (a Auth) LandingURL() string {
	if a.AppURL != "" {
		return a.AppURL
	}

	return "/"
}

// LogoutURL is where the provider returns the browser after ending the session.
func (a Auth) LogoutURL() string {
	if a.PostLogoutURL != "" {
		return a.PostLogoutURL
	}

	return a.LandingURL()
}

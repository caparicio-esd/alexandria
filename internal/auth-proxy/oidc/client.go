// Package oidc is the driven adapter for the OpenID Provider, reached over its
// HTTP API.
//
// It speaks OAuth 2.0 and OpenID Connect and nothing about this node: the
// endpoints come from the provider's own discovery document rather than from
// configuration, so pointing the deployment at a different Zitadel instance —
// or at another compliant provider — is a URL change and nothing more.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"resty.dev/v3"
)

var (
	// ErrProvider reports that the provider answered, and refused. The caller
	// is at fault: a stale authorization code, a revoked refresh token.
	ErrProvider = errors.New("identity provider refused the request")
	// ErrUnavailable reports that the provider could not be reached, or
	// answered in a way no client can act on. Ours to fix, not the caller's.
	ErrUnavailable = errors.New("identity provider unavailable")
	// ErrNotDiscovered reports a call made before the discovery document was
	// read, which is the state the node is in while the provider is still
	// coming up.
	ErrNotDiscovered = errors.New("identity provider not discovered yet")
)

// discoveryPath is fixed by RFC 8414 and by OpenID Connect Discovery.
const discoveryPath = "/.well-known/openid-configuration"

// Metadata is the subset of the discovery document this node uses.
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Tokens is what the token endpoint hands back, whichever grant asked for it.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// ExpiresAt turns the relative lifetime into an absolute instant, against the
// clock the caller supplies so a session's expiry stays testable.
func (t Tokens) ExpiresAt(now time.Time) time.Time {
	if t.ExpiresIn <= 0 {
		return time.Time{}
	}

	return now.Add(time.Duration(t.ExpiresIn) * time.Second)
}

// Introspection is the answer to RFC 7662, which is how an opaque access token
// is resolved into claims.
type Introspection struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	Username string `json:"username"`
	Subject  string `json:"sub"`
	Audience any    `json:"aud"`
	Issuer   string `json:"iss"`
	Expires  int64  `json:"exp"`
	// Claims carries everything else the provider chose to include — the role
	// URNs among them — since introspection returns the same claim set the JWT
	// would have carried.
	Claims map[string]any `json:"-"`
}

// errorResponse is the OAuth 2.0 error shape, which every endpoint here shares.
type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// Client talks to one provider.
//
// The discovery document is fetched once and cached: it changes when the
// provider is reconfigured, which is not something to pay for on every request,
// and the JWKS — the part that does rotate — is refreshed on its own schedule
// by the verifier.
type Client struct {
	http         *resty.Client
	issuer       string
	providerURL  string
	clientID     string
	clientSecret string
	logger       *slog.Logger

	mu   sync.RWMutex
	meta *Metadata
}

// New builds a client against the provider at providerURL, validating tokens
// against issuer. The two differ only where the deployment publishes the
// provider somewhere other than where this process reaches it.
func New(issuer, providerURL, clientID, clientSecret string, timeout time.Duration, logger *slog.Logger) (*Client, error) {
	parsed, err := url.Parse(providerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: parsing provider url %q: %w", providerURL, err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("oidc: provider url %q must be absolute", providerURL)
	}

	if logger == nil {
		logger = slog.Default()
	}

	client := resty.New().
		SetTimeout(timeout).
		SetHeader("Accept", "application/json")

	return &Client{
		http:         client,
		issuer:       strings.TrimSuffix(issuer, "/"),
		providerURL:  strings.TrimSuffix(providerURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		logger:       logger,
	}, nil
}

// Close releases the transport.
func (c *Client) Close() error {
	if err := c.http.Close(); err != nil {
		return fmt.Errorf("oidc: closing the http client: %w", err)
	}

	return nil
}

// Discover reads the provider's configuration and caches it.
//
// The issuer in the document is checked against the configured one, which is
// the whole reason discovery is safe to trust: a document served from somewhere
// else cannot claim to speak for this issuer.
func (c *Client) Discover(ctx context.Context) (Metadata, error) {
	var (
		meta Metadata
		fail errorResponse
	)

	res, err := c.http.R().
		SetContext(ctx).
		SetResult(&meta).
		SetResultError(&fail).
		Get(c.providerURL + discoveryPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("oidc: reading %s: %w: %w", discoveryPath, ErrUnavailable, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.IsStatusFailure() {
		return Metadata{}, fmt.Errorf("oidc: reading %s: status %d: %w",
			discoveryPath, res.StatusCode(), ErrUnavailable)
	}

	if meta.Issuer != c.issuer {
		return Metadata{}, fmt.Errorf(
			"oidc: discovery document names issuer %q, configured issuer is %q: %w",
			meta.Issuer, c.issuer, ErrUnavailable)
	}

	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return Metadata{}, fmt.Errorf("oidc: discovery document is missing an endpoint: %w", ErrUnavailable)
	}

	c.mu.Lock()
	c.meta = &meta
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "provider discovered",
		"issuer", meta.Issuer, "jwks_uri", meta.JWKSURI)

	return meta, nil
}

// Metadata returns the cached discovery document, if there is one.
func (c *Client) Metadata() (Metadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.meta == nil {
		return Metadata{}, false
	}

	return *c.meta, true
}

// Issuer is the identifier every token must name.
func (c *Client) Issuer() string { return c.issuer }

// ClientID is this node's registered application.
func (c *Client) ClientID() string { return c.clientID }

// AuthorizeParams is one authorization request, before it becomes a URL.
type AuthorizeParams struct {
	RedirectURL         string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	Prompt              string
	LoginHint           string
	OrganizationID      string
	IDPHint             string
	AdditionalAudiences []string
}

// AuthorizationURL builds the address the browser is redirected to.
//
// PKCE is not optional here even though this node is a confidential client:
// the code is handed to a browser, and S256 is what stops it being usable by
// anything that intercepts the redirect.
func (c *Client) AuthorizationURL(params AuthorizeParams) (string, error) {
	meta, ok := c.Metadata()
	if !ok {
		return "", ErrNotDiscovered
	}

	query := url.Values{}
	query.Set("client_id", c.clientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", params.RedirectURL)
	query.Set("scope", strings.Join(params.Scopes, " "))
	query.Set("state", params.State)
	query.Set("nonce", params.Nonce)
	query.Set("code_challenge", params.CodeChallenge)
	query.Set("code_challenge_method", "S256")

	if params.Prompt != "" {
		query.Set("prompt", params.Prompt)
	}

	if params.LoginHint != "" {
		query.Set("login_hint", params.LoginHint)
	}

	// Zitadel's own extensions, both spelled as reserved scopes rather than
	// parameters: one pins the login to an organization, the other skips the
	// account picker for a known external provider.
	if params.OrganizationID != "" {
		query.Set("scope", query.Get("scope")+" urn:zitadel:iam:org:id:"+params.OrganizationID)
	}

	if params.IDPHint != "" {
		query.Set("idp_hint", params.IDPHint)
	}

	for _, audience := range params.AdditionalAudiences {
		query.Set("scope", query.Get("scope")+" urn:zitadel:iam:org:project:id:"+audience+":aud")
	}

	return meta.AuthorizationEndpoint + "?" + query.Encode(), nil
}

// Exchange trades an authorization code for tokens.
func (c *Client) Exchange(ctx context.Context, code, verifier, redirectURL string) (*Tokens, error) {
	return c.token(ctx, map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURL,
		"code_verifier": verifier,
	})
}

// Refresh renews a session from its refresh token.
//
// The provider may return a new refresh token, and with rotation enabled it
// always does — the caller must store whatever comes back rather than keeping
// the one it sent.
func (c *Client) Refresh(ctx context.Context, refreshToken string, scopes []string) (*Tokens, error) {
	form := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	if len(scopes) > 0 {
		form["scope"] = strings.Join(scopes, " ")
	}

	return c.token(ctx, form)
}

// ClientCredentials mints a token for a service account, which is how another
// node of the dataspace authenticates: no browser, no session, no user.
func (c *Client) ClientCredentials(ctx context.Context, clientID, clientSecret string, scopes []string) (*Tokens, error) {
	form := map[string]string{"grant_type": "client_credentials"}
	if len(scopes) > 0 {
		form["scope"] = strings.Join(scopes, " ")
	}

	return c.tokenAs(ctx, form, clientID, clientSecret)
}

// token posts a grant authenticated as this node.
func (c *Client) token(ctx context.Context, form map[string]string) (*Tokens, error) {
	return c.tokenAs(ctx, form, c.clientID, c.clientSecret)
}

// tokenAs posts a grant authenticated as the given client.
//
// The credentials go in the Authorization header when there is a secret
// (client_secret_basic) and in the body otherwise (none, a public client under
// PKCE) — the two spellings the token endpoint accepts.
func (c *Client) tokenAs(ctx context.Context, form map[string]string, clientID, clientSecret string) (*Tokens, error) {
	meta, ok := c.Metadata()
	if !ok {
		return nil, ErrNotDiscovered
	}

	var (
		tokens Tokens
		fail   errorResponse
	)

	request := c.http.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(form).
		SetResult(&tokens).
		SetResultError(&fail)

	if clientSecret == "" {
		request.SetFormData(map[string]string{"client_id": clientID})
	} else {
		request.SetBasicAuth(clientID, clientSecret)
	}

	res, err := request.Post(meta.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("oidc: calling the token endpoint: %w: %w", ErrUnavailable, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.IsStatusFailure() {
		return nil, tokenError(res.StatusCode(), fail)
	}

	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("oidc: the token endpoint returned no access token: %w", ErrUnavailable)
	}

	return &tokens, nil
}

// tokenError classifies what the token endpoint refused.
//
// A 4xx is the caller's — an expired code, a revoked refresh token — and a 5xx
// is the provider's. Collapsing the two would have a browser retry a login that
// can never succeed, or give up on one that would.
func tokenError(status int, fail errorResponse) error {
	detail := fail.Error
	if fail.Description != "" {
		detail = fail.Error + ": " + fail.Description
	}

	if detail == "" {
		detail = fmt.Sprintf("status %d", status)
	}

	if status >= http.StatusInternalServerError {
		return fmt.Errorf("oidc: token endpoint: %s: %w", detail, ErrUnavailable)
	}

	return fmt.Errorf("oidc: token endpoint: %s: %w", detail, ErrProvider)
}

// UserInfo reads the claims the provider is willing to release for an access
// token. It is the one call that proves a token is live without introspection
// rights.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	meta, ok := c.Metadata()
	if !ok {
		return nil, ErrNotDiscovered
	}

	if meta.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("oidc: the provider publishes no userinfo endpoint: %w", ErrUnavailable)
	}

	claims := map[string]any{}

	res, err := c.http.R().
		SetContext(ctx).
		SetAuthToken(accessToken).
		SetResult(&claims).
		Get(meta.UserinfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("oidc: calling userinfo: %w: %w", ErrUnavailable, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode() == http.StatusUnauthorized {
		return nil, fmt.Errorf("oidc: userinfo rejected the token: %w", ErrProvider)
	}

	if res.IsStatusFailure() {
		return nil, fmt.Errorf("oidc: userinfo: status %d: %w", res.StatusCode(), ErrUnavailable)
	}

	return claims, nil
}

// Introspect resolves a token at the provider, per RFC 7662.
//
// It is what makes an opaque access token usable, and the only way to see a
// revocation the moment it happens. It costs a round trip per call, which is
// why it is not the default path.
func (c *Client) Introspect(ctx context.Context, token string) (*Introspection, error) {
	meta, ok := c.Metadata()
	if !ok {
		return nil, ErrNotDiscovered
	}

	if meta.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("oidc: the provider publishes no introspection endpoint: %w", ErrUnavailable)
	}

	claims := map[string]any{}

	res, err := c.http.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBasicAuth(c.clientID, c.clientSecret).
		SetFormData(map[string]string{"token": token, "token_type_hint": "access_token"}).
		SetResult(&claims).
		Post(meta.IntrospectionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("oidc: calling introspection: %w: %w", ErrUnavailable, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.IsStatusFailure() {
		return nil, fmt.Errorf("oidc: introspection: status %d: %w", res.StatusCode(), ErrUnavailable)
	}

	return introspectionFrom(claims), nil
}

// introspectionFrom projects the raw claim set onto the typed fields, keeping
// the whole map alongside: the roles this deployment gates on live in a claim
// whose name is configuration, not something this package can spell.
func introspectionFrom(claims map[string]any) *Introspection {
	result := &Introspection{Claims: claims} //nolint:exhaustruct // filled in below

	result.Active, _ = claims["active"].(bool)
	result.Scope, _ = claims["scope"].(string)
	result.ClientID, _ = claims["client_id"].(string)
	result.Username, _ = claims["username"].(string)
	result.Subject, _ = claims["sub"].(string)
	result.Issuer, _ = claims["iss"].(string)
	result.Audience = claims["aud"]

	if exp, ok := claims["exp"].(float64); ok {
		result.Expires = int64(exp)
	}

	return result
}

// Revoke invalidates a token at the provider. A logout that only drops the
// cookie leaves a refresh token alive for its full lifetime, which is a session
// the user believes they ended.
func (c *Client) Revoke(ctx context.Context, token, hint string) error {
	meta, ok := c.Metadata()
	if !ok {
		return ErrNotDiscovered
	}

	if meta.RevocationEndpoint == "" {
		return fmt.Errorf("oidc: the provider publishes no revocation endpoint: %w", ErrUnavailable)
	}

	res, err := c.http.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBasicAuth(c.clientID, c.clientSecret).
		SetFormData(map[string]string{"token": token, "token_type_hint": hint}).
		Post(meta.RevocationEndpoint)
	if err != nil {
		return fmt.Errorf("oidc: calling revocation: %w: %w", ErrUnavailable, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.IsStatusFailure() {
		return fmt.Errorf("oidc: revocation: status %d: %w", res.StatusCode(), ErrUnavailable)
	}

	return nil
}

// EndSessionURL is where the browser goes to end the session at the provider
// itself. Dropping our cookie logs the user out of this node; only this logs
// them out of Zitadel, which is what "log out" means to anyone who then
// presses the back button.
func (c *Client) EndSessionURL(idToken, postLogoutURL, state string) (string, bool) {
	meta, ok := c.Metadata()
	if !ok || meta.EndSessionEndpoint == "" {
		return "", false
	}

	query := url.Values{}
	query.Set("client_id", c.clientID)

	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}

	if postLogoutURL != "" {
		query.Set("post_logout_redirect_uri", postLogoutURL)
	}

	if state != "" {
		query.Set("state", state)
	}

	return meta.EndSessionEndpoint + "?" + query.Encode(), true
}

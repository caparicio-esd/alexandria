// Package rest is the driving adapter of the auth-proxy context: the /auth
// routes, and the middleware every other route in the API passes through.
//
// It is thicker than the other adapters in this tree, and deliberately so. The
// authorization code flow is a protocol made of redirects, cookies and headers;
// there is no use case underneath it that could be stated without them, and
// hiding the round trip behind a service would only move HTTP into a package
// that pretends not to know about it.
package rest

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/identity"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/oidc"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/session"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/token"
	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/gin-gonic/gin"
)

// Deps is everything the adapter needs, wired at the context's composition
// root.
type Deps struct {
	// Client talks to the provider.
	Client *oidc.Client
	// Sessions seals and opens the browser's cookie.
	Sessions *session.Manager
	// Verifier resolves a credential into a caller.
	Verifier *token.Verifier
	// Config is this context's section of the deployment document.
	Config config.Auth
	// Now is the clock, injected so expiry stays deterministic under test.
	Now func() time.Time
	// Logger is this context's logger.
	Logger *slog.Logger
}

// AuthRouter is the whole HTTP boundary of the context: the proxy's own routes
// and the guard in front of everything else.
type AuthRouter struct {
	client   *oidc.Client
	sessions *session.Manager
	verifier *token.Verifier
	cfg      config.Auth
	now      func() time.Time
	logger   *slog.Logger
}

// NewAuthRouter wires the adapter onto what it drives.
func NewAuthRouter(deps Deps) *AuthRouter {
	now := deps.Now
	if now == nil {
		now = time.Now
	}

	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &AuthRouter{
		client:   deps.Client,
		sessions: deps.Sessions,
		verifier: deps.Verifier,
		cfg:      deps.Config,
		now:      now,
		logger:   logger,
	}
}

// RegisterPublic mounts the routes that must answer before there is anything to
// authenticate with.
//
//	GET  /auth/login     starts the login, redirecting to the provider
//	GET  /auth/callback  completes it and seals the session cookie
//	POST /auth/refresh   renews the session from its refresh token
//	POST /auth/logout    drops the session here and ends it at the provider
//	POST /auth/token     mints a token for a service account
//
// They are mounted on a group taken before the guard is installed, which is
// what keeps them reachable: a login route behind an authentication check is a
// node nobody can log in to.
func (r *AuthRouter) RegisterPublic(api *gin.RouterGroup) {
	auth := api.Group("/auth")

	auth.GET("/login", r.login)
	auth.GET("/callback", r.callback)
	auth.POST("/refresh", r.refresh)
	auth.POST("/logout", r.logout)
	auth.POST("/token", r.machineToken)
}

// Register mounts the routes that describe an already authenticated caller.
// They sit behind the guard like everything else.
//
//	GET /auth/session   the caller, as this node sees them
//	GET /auth/userinfo  the caller, as the provider describes them
func (r *AuthRouter) Register(api *gin.RouterGroup) {
	auth := api.Group("/auth")

	auth.GET("/session", r.currentSession)
	auth.GET("/userinfo", r.userinfo)
}

// ===== HTTP handlers =========================================================

// login starts the authorization code flow.
//
// It answers a redirect by default and a JSON document when asked, because the
// two callers want different things: a browser navigating to a protected page
// wants to be sent onwards, while a single-page application wants the URL to
// open in a popup or a tab it controls.
func (r *AuthRouter) login(c *gin.Context) {
	verifier, err := oidc.NewVerifier()
	if err != nil {
		respondError(c, err)

		return
	}

	state, err := oidc.NewState()
	if err != nil {
		respondError(c, err)

		return
	}

	nonce, err := oidc.NewNonce()
	if err != nil {
		respondError(c, err)

		return
	}

	target, err := r.client.AuthorizationURL(oidc.AuthorizeParams{ //nolint:exhaustruct // the hints are optional
		RedirectURL:    r.cfg.RedirectURL,
		Scopes:         r.cfg.Scopes,
		State:          state,
		Nonce:          nonce,
		CodeChallenge:  oidc.Challenge(verifier),
		Prompt:         c.Query("prompt"),
		LoginHint:      c.Query("login_hint"),
		OrganizationID: c.Query("organization"),
		IDPHint:        c.Query("idp"),
	})
	if err != nil {
		respondError(c, err)

		return
	}

	flow := session.Flow{ //nolint:exhaustruct // Expiry is stamped by SaveFlow
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		Return:   r.safeReturn(c.Query("return_to")),
	}

	if err := r.sessions.SaveFlow(c.Writer, flow, r.now()); err != nil {
		respondError(c, err)

		return
	}

	if wantsJSON(c) {
		c.JSON(http.StatusOK, loginResp{AuthorizationURL: target})

		return
	}

	c.Redirect(http.StatusFound, target)
}

// callback completes the flow: it proves the code answers this node's own
// request, exchanges it, and seals the result into the session cookie.
func (r *AuthRouter) callback(c *gin.Context) {
	// The flow cookie is single-use whatever happens next, so it goes first:
	// a failed attempt must not leave a verifier lying around for a second try.
	defer r.sessions.ClearFlow(c.Writer)

	flow, err := r.sessions.LoadFlow(c.Request, r.now())
	if err != nil {
		respondError(c, err)

		return
	}

	if providerError := c.Query("error"); providerError != "" {
		respondError(c, fmt.Errorf("callback: the provider refused the login (%s): %w",
			providerError, oidc.ErrProvider))

		return
	}

	code := c.Query("code")
	if code == "" {
		respondError(c, fmt.Errorf("callback: no authorization code: %w", errBadRequest))

		return
	}

	// Constant-time is not required here — the state is single-use and lives
	// for ten minutes — but a mismatch is exactly the cross-site request
	// forgery the parameter exists to catch, so it is refused loudly.
	if c.Query("state") != flow.State {
		respondError(c, fmt.Errorf("callback: state does not match this node's request: %w",
			errBadRequest))

		return
	}

	tokens, err := r.client.Exchange(c.Request.Context(), code, flow.Verifier, r.cfg.RedirectURL)
	if err != nil {
		respondError(c, err)

		return
	}

	// The nonce is what ties the token to this browser's login. It is checked
	// before the access token is trusted for anything, and before a cookie
	// exists to carry either.
	if tokens.IDToken != "" {
		if err := r.verifier.VerifyID(c.Request.Context(), tokens.IDToken, flow.Nonce, r.client.ClientID()); err != nil {
			respondError(c, err)

			return
		}
	}

	principal, err := r.verifier.Verify(c.Request.Context(), tokens.AccessToken)
	if err != nil {
		respondError(c, err)

		return
	}

	if err := r.persist(c, principal.Subject, tokens); err != nil {
		respondError(c, err)

		return
	}

	r.logger.InfoContext(c.Request.Context(), "session established",
		"subject", principal.Subject, "machine", principal.Machine)

	destination := flow.Return
	if destination == "" {
		destination = r.cfg.LandingURL()
	}

	if wantsJSON(c) {
		c.JSON(http.StatusOK, newSessionResp(principal, tokens.ExpiresAt(r.now())))

		return
	}

	c.Redirect(http.StatusFound, destination)
}

// refresh renews the session from its refresh token.
//
// It is public because by the time it is called the access token is, by
// definition, no longer good enough to pass the guard — the refresh token in
// the sealed cookie is the credential, and it is checked by the provider.
func (r *AuthRouter) refresh(c *gin.Context) {
	state, err := r.sessions.Load(c.Request, r.now())
	if err != nil {
		respondError(c, err)

		return
	}

	renewed, principal, err := r.renew(c, state)
	if err != nil {
		respondError(c, err)

		return
	}

	c.JSON(http.StatusOK, newSessionResp(principal, renewed.TokenExpiry))
}

// logout ends the session here and, where the provider supports it, there.
//
// The refresh token is revoked rather than merely forgotten: a cookie dropped
// on this side leaves a credential alive at the provider for its full lifetime,
// which is a session the user believes they have ended.
func (r *AuthRouter) logout(c *gin.Context) {
	state, err := r.sessions.Load(c.Request, r.now())
	if err != nil && !errors.Is(err, session.ErrNoSession) && !errors.Is(err, session.ErrInvalidSession) {
		respondError(c, err)

		return
	}

	// Unconditional: a logout must clear the cookie even when the revocation
	// below fails, or a provider outage becomes a session nobody can end.
	r.sessions.Clear(c.Writer)

	if state.RefreshToken != "" {
		if err := r.client.Revoke(c.Request.Context(), state.RefreshToken, "refresh_token"); err != nil {
			r.logger.WarnContext(c.Request.Context(), "revoking the refresh token failed",
				"subject", state.Subject, "err", err)
		}
	}

	endSession, ok := r.client.EndSessionURL(state.IDToken, r.cfg.LogoutURL(), "")

	if !wantsJSON(c) && ok {
		c.Redirect(http.StatusFound, endSession)

		return
	}

	c.JSON(http.StatusOK, logoutResp{EndSessionURL: endSession})
}

// machineToken proxies the client credentials grant.
//
// It is what keeps the promise whole for a service account: another node of the
// dataspace, or a CI job, authenticates against /api/v1/auth like everything
// else and never learns the provider's address. The credentials are the
// caller's own, passed through — this node mints nothing on their behalf.
func (r *AuthRouter) machineToken(c *gin.Context) {
	var req machineTokenReq

	// Both spellings are accepted because both callers exist: a form post is
	// what an OAuth client library sends, and JSON is what everything else in
	// this API speaks.
	if err := c.ShouldBind(&req); err != nil {
		respondError(c, fmt.Errorf("token: %s: %w", err.Error(), errBadRequest))

		return
	}

	if req.ClientID == "" || req.ClientSecret == "" {
		respondError(c, fmt.Errorf("token: client_id and client_secret are required: %w", errBadRequest))

		return
	}

	scopes := strings.Fields(req.Scope)
	if len(scopes) == 0 {
		scopes = r.cfg.Scopes
	}

	tokens, err := r.client.ClientCredentials(c.Request.Context(), req.ClientID, req.ClientSecret, scopes)
	if err != nil {
		respondError(c, err)

		return
	}

	// The refresh token, if the provider sent one, is dropped: this response
	// goes to a machine that can ask again with its own credentials, and a
	// long-lived credential handed out over an API is one more thing to leak.
	c.JSON(http.StatusOK, tokenResp{
		AccessToken: tokens.AccessToken,
		TokenType:   tokens.TokenType,
		ExpiresIn:   tokens.ExpiresIn,
		Scope:       tokens.Scope,
	})
}

// currentSession describes the caller, from the token the guard already
// verified. It contacts nothing: this is what a frontend polls to decide
// whether to render a login button.
func (r *AuthRouter) currentSession(c *gin.Context) {
	principal := identity.FromContext(c.Request.Context())
	if principal == nil {
		respondError(c, fmt.Errorf("session: no caller on the request: %w", token.ErrUnauthenticated))

		return
	}

	c.JSON(http.StatusOK, newSessionResp(principal, principal.ExpiresAt))
}

// userinfo asks the provider what it is willing to say about the caller. It
// exists so a frontend that needs a claim this node does not project onto a
// Principal can still get it, without being handed the provider's address.
func (r *AuthRouter) userinfo(c *gin.Context) {
	accessToken, err := r.credential(c)
	if err != nil {
		respondError(c, err)

		return
	}

	claims, err := r.client.UserInfo(c.Request.Context(), accessToken)
	if err != nil {
		respondError(c, err)

		return
	}

	c.JSON(http.StatusOK, claims)
}

// ===== Session plumbing ======================================================

// persist seals a token response into the session cookie.
func (r *AuthRouter) persist(c *gin.Context, subject string, tokens *oidc.Tokens) error {
	now := r.now()

	return r.sessions.Save(c.Writer, session.State{ //nolint:exhaustruct // Expiry is stamped by Save
		Subject:      subject,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		Scope:        tokens.Scope,
		TokenExpiry:  tokens.ExpiresAt(now),
		IssuedAt:     now,
	}, now)
}

// renew exchanges the refresh token for a new set and re-seals the cookie.
//
// Whatever refresh token comes back is the one that is stored: with rotation
// enabled — Zitadel's default — the one just used is already dead, and keeping
// it would end the session on the next renewal.
func (r *AuthRouter) renew(c *gin.Context, state session.State) (session.State, *identity.Principal, error) {
	if state.RefreshToken == "" {
		return session.State{}, nil, fmt.Errorf(
			"session: no refresh token, the login did not request offline_access: %w",
			token.ErrUnauthenticated)
	}

	tokens, err := r.client.Refresh(c.Request.Context(), state.RefreshToken, nil)
	if err != nil {
		// A provider that refuses the refresh token has ended the session, and
		// the cookie holding it is now worthless: dropping it here is what
		// turns an endless 401 loop into a fresh login.
		if errors.Is(err, oidc.ErrProvider) {
			r.sessions.Clear(c.Writer)
		}

		return session.State{}, nil, err
	}

	principal, err := r.verifier.Verify(c.Request.Context(), tokens.AccessToken)
	if err != nil {
		return session.State{}, nil, err
	}

	if tokens.RefreshToken == "" {
		tokens.RefreshToken = state.RefreshToken
	}

	if tokens.IDToken == "" {
		tokens.IDToken = state.IDToken
	}

	if err := r.persist(c, principal.Subject, tokens); err != nil {
		return session.State{}, nil, err
	}

	now := r.now()

	return session.State{ //nolint:exhaustruct // the caller only reads the expiry
		Subject:     principal.Subject,
		AccessToken: tokens.AccessToken,
		TokenExpiry: tokens.ExpiresAt(now),
	}, principal, nil
}

// credential recovers the caller's access token, from the session cookie or
// from the Authorization header.
func (r *AuthRouter) credential(c *gin.Context) (string, error) {
	if bearer := bearerToken(c.Request); bearer != "" {
		return bearer, nil
	}

	state, err := r.sessions.Load(c.Request, r.now())
	if err != nil {
		return "", err
	}

	return state.AccessToken, nil
}

// safeReturn keeps the login from becoming an open redirect.
//
// A path is allowed, an absolute URL only when it is on the origin this node
// already sends browsers to, and anything else falls back to that origin. The
// parameter is attacker-controlled — it arrives in a link — and an unvalidated
// one turns the login into a credible phishing hop.
func (r *AuthRouter) safeReturn(raw string) string {
	if raw == "" {
		return ""
	}

	// A protocol-relative "//evil.example" parses as a host, not a path, and is
	// the classic way past a naive prefix check.
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}

	target, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	landing, err := url.Parse(r.cfg.LandingURL())
	if err != nil {
		return ""
	}

	if target.Scheme == landing.Scheme && target.Host == landing.Host {
		return raw
	}

	r.logger.Warn("refusing an off-origin return_to", "return_to", raw)

	return ""
}

// wantsJSON reports whether the caller would rather have a document than a
// redirect: an explicit ?response=json, or an Accept header that asks for JSON
// without accepting HTML — which is what fetch() sends and a browser navigation
// does not.
func wantsJSON(c *gin.Context) bool {
	if c.Query("response") == "json" {
		return true
	}

	accept := c.GetHeader("Accept")

	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

// bearerToken pulls the credential out of the Authorization header, or returns
// "" when there is none to pull.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")

	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}

	return strings.TrimSpace(header[len(prefix):])
}

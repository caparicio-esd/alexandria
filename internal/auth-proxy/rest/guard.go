package rest

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/identity"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/session"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/token"
	"github.com/gin-gonic/gin"
)

// PrincipalKey is where the authenticated caller is filed on the gin context,
// for a handler that has the *gin.Context but not the request context.
// identity.FromContext is the way most code should reach it.
const PrincipalKey = "auth.principal"

// refreshWindow is how long before expiry the guard renews a session rather
// than letting the next call fail. Without it every session produces one 401 an
// hour that a correct client has to recover from, and an incorrect one does
// not.
const refreshWindow = 30 * time.Second

// Protect is the middleware every route under the API prefix passes through.
//
// It accepts two credentials and treats them the same once resolved: the sealed
// session cookie, which is what a browser has, and a Bearer token, which is what
// another node or a CLI has. Both end as a Principal on the request context, so
// nothing downstream has to know which door the caller came through.
func (r *AuthRouter) Protect() gin.HandlerFunc {
	return func(c *gin.Context) {
		// A CORS preflight carries no credentials by definition, and refusing
		// it would break the browser before the real request is ever sent.
		if c.Request.Method == http.MethodOptions {
			c.Next()

			return
		}

		if !r.verifier.Ready() {
			// Nothing can be verified yet: the provider is still coming up.
			// Answering 401 here would tell a client its perfectly good
			// credential is bad, and have it throw the session away.
			respondError(c, fmt.Errorf("guard: %w", token.ErrNotReady))

			return
		}

		principal, err := r.authenticate(c)
		if err != nil {
			respondError(c, err)

			return
		}

		if !principal.HasEveryRole(r.cfg.RequiredRoles) {
			respondError(c, fmt.Errorf("guard: %q lacks one of %v: %w",
				principal.Subject, r.cfg.RequiredRoles, errForbidden))

			return
		}

		c.Set(PrincipalKey, principal)
		c.Request = c.Request.WithContext(identity.WithPrincipal(c.Request.Context(), principal))

		c.Next()
	}
}

// authenticate resolves whichever credential the request carries.
//
// The header is tried first: a call that presents a Bearer token is asking to
// be seen as that token's subject, even from a browser that happens to hold a
// session cookie for somebody else.
func (r *AuthRouter) authenticate(c *gin.Context) (*identity.Principal, error) {
	if bearer := bearerToken(c.Request); bearer != "" {
		principal, err := r.verifier.Verify(c.Request.Context(), bearer)
		if err != nil {
			return nil, fmt.Errorf("guard: bearer token: %w", err)
		}

		return principal, nil
	}

	state, err := r.sessions.Load(c.Request, r.now())
	if err != nil {
		if errors.Is(err, session.ErrInvalidSession) {
			// A cookie that will not open is never going to open. Clearing it
			// stops the browser presenting it on every subsequent request.
			r.sessions.Clear(c.Writer)
		}

		return nil, fmt.Errorf("guard: %w", err)
	}

	// Renewed before it expires rather than after it fails, so an active
	// session never surfaces the token's lifetime to the user at all.
	if r.expiring(state) && state.RefreshToken != "" {
		_, principal, renewErr := r.renew(c, state)
		if renewErr != nil {
			return nil, fmt.Errorf("guard: renewing the session: %w", renewErr)
		}

		return principal, nil
	}

	principal, err := r.verifier.Verify(c.Request.Context(), state.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("guard: session token: %w", err)
	}

	return principal, nil
}

// expiring reports whether the session's access token is close enough to its
// deadline to be worth renewing now. A session with no recorded expiry is left
// alone: the token itself carries one, and the verifier enforces it.
func (r *AuthRouter) expiring(state session.State) bool {
	if state.TokenExpiry.IsZero() {
		return false
	}

	return r.now().Add(refreshWindow).After(state.TokenExpiry)
}

// RequireRole builds middleware for a route that needs more than
// authentication. It is not used by the guard — which applies the deployment's
// blanket requirement — but by any module with a route of its own to gate.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := identity.FromContext(c.Request.Context())
		if principal == nil {
			respondError(c, fmt.Errorf("guard: no caller on the request: %w", token.ErrUnauthenticated))

			return
		}

		if !principal.HasEveryRole(roles) {
			respondError(c, fmt.Errorf("guard: %q lacks one of %v: %w",
				principal.Subject, roles, errForbidden))

			return
		}

		c.Next()
	}
}

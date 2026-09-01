package rest

import (
	"errors"
	"net/http"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/oidc"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/session"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/token"
	"github.com/gin-gonic/gin"
)

// errorBody is the error shape this API speaks. It matches the one the other
// contexts answer with, deliberately: a client should not have to branch on
// which part of the node refused it.
type errorBody struct {
	Error string `json:"error"`
	// Field names the offending input when there is one to name.
	Field string `json:"field,omitempty"`
}

// challenge is the WWW-Authenticate header a 401 carries, so a client that
// speaks OAuth knows what kind of credential is missing rather than guessing
// from the status alone.
const challenge = `Bearer realm="alexandria", error="invalid_token"`

// respondError is the only translation table between this context's errors and
// HTTP. Nothing else in the package chooses a status code.
//
// The rule it encodes: a credential problem is 401, a permission problem is
// 403, a provider that refused is 502 in the sense of "upstream said no" but is
// reported as 401 when it refused the caller's own credential, and a provider
// that could not be reached is 503 — because retrying later is the right thing
// to do, and retrying a 401 is not.
func respondError(c *gin.Context, err error) {
	// Filed on the context rather than logged here: the access log emits one
	// record per request and picks this up, so logging in both places would
	// double-count every failure.
	_ = c.Error(err)

	switch {
	case errors.Is(err, token.ErrUnauthenticated),
		errors.Is(err, session.ErrInvalidSession),
		errors.Is(err, session.ErrNoSession):
		c.Header("WWW-Authenticate", challenge)
		c.AbortWithStatusJSON(http.StatusUnauthorized, errorBody{Error: "not authenticated"})

	case errors.Is(err, errForbidden):
		c.AbortWithStatusJSON(http.StatusForbidden, errorBody{Error: "not allowed"})

	case errors.Is(err, oidc.ErrProvider):
		// The provider answered and refused: a stale authorization code, a
		// revoked refresh token. Nothing the node can retry on the caller's
		// behalf, and nothing that says anything is broken here.
		c.Header("WWW-Authenticate", challenge)
		c.AbortWithStatusJSON(http.StatusUnauthorized, errorBody{Error: "the identity provider refused the request"})

	case errors.Is(err, oidc.ErrUnavailable),
		errors.Is(err, oidc.ErrNotDiscovered),
		errors.Is(err, token.ErrNotReady):
		// Retry-After is set because this is genuinely temporary: the provider
		// is coming up, or briefly unreachable, and the node keeps trying.
		c.Header("Retry-After", "5")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable,
			errorBody{Error: "the identity provider is unavailable"})

	case errors.Is(err, errBadRequest):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorBody{Error: err.Error()})

	default:
		// Anything unclassified is ours, and answered opaque: the cause reaches
		// the log through c.Error above, not the caller.
		c.AbortWithStatusJSON(http.StatusInternalServerError, errorBody{Error: "internal error"})
	}
}

var (
	// errForbidden reports an authenticated caller who lacks what the route
	// requires. It is separate from the authentication errors because the
	// remedy is different: logging in again will not help.
	errForbidden = errors.New("forbidden")
	// errBadRequest reports a malformed call into this context. Its message is
	// echoed to the caller, so it must never carry anything internal.
	errBadRequest = errors.New("bad request")
)

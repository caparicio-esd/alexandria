package rest

import (
	"time"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/identity"
)

// loginResp is the answer to a login started by a client that would rather open
// the provider itself than be redirected.
type loginResp struct {
	AuthorizationURL string `json:"authorization_url"`
}

// logoutResp carries the address that ends the session at the provider, for a
// client that has to navigate there itself.
type logoutResp struct {
	EndSessionURL string `json:"end_session_url,omitempty"`
}

// machineTokenReq is the client credentials grant, in either of the two
// spellings a caller may send it: form-encoded, as an OAuth library does, or
// JSON, as the rest of this API does.
type machineTokenReq struct {
	ClientID     string `form:"client_id"     json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	Scope        string `form:"scope"         json:"scope,omitempty"`
}

// tokenResp is a minted access token. It deliberately carries no refresh token:
// the caller is a machine holding its own credentials, and it can ask again.
type tokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// sessionResp describes the authenticated caller.
//
// No token of any kind appears in it. A frontend gets who it is talking as and
// when that stops being true, which is everything it needs to render, and
// nothing it could leak.
type sessionResp struct {
	Subject      string    `json:"subject"`
	Username     string    `json:"username,omitempty"`
	Email        string    `json:"email,omitempty"`
	Name         string    `json:"name,omitempty"`
	Organization string    `json:"organization,omitempty"`
	Roles        []string  `json:"roles"`
	Scopes       []string  `json:"scopes"`
	Machine      bool      `json:"machine"`
	ExpiresAt    time.Time `json:"expires_at,omitzero"`
}

// newSessionResp renders a principal for the wire.
func newSessionResp(principal *identity.Principal, expiry time.Time) sessionResp {
	roles := principal.Roles
	if roles == nil {
		// An empty array rather than null: a client iterating over the field
		// should not have to special-case a caller with no roles.
		roles = []string{}
	}

	scopes := principal.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	return sessionResp{
		Subject:      principal.Subject,
		Username:     principal.Username,
		Email:        principal.Email,
		Name:         principal.Name,
		Organization: principal.Organization,
		Roles:        roles,
		Scopes:       scopes,
		Machine:      principal.Machine,
		ExpiresAt:    expiry,
	}
}

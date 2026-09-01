package authproxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// fakeProvider is an OpenID Provider that answers the four endpoints this
// context uses: discovery, keys, token and revocation.
//
// A fake rather than a running Zitadel, because what is under test is this
// node's half of the protocol — that the state and the verifier are checked,
// that the cookie is sealed, that the guard refuses what it should. Zitadel's
// own conformance is Zitadel's problem, and standing one up per test run would
// buy no coverage of the code in this package.
type fakeProvider struct {
	server *httptest.Server
	key    jwk.Key
	public jwk.Set

	// roles is the claim minted into every token, so a test can arrange a
	// caller who lacks what the deployment requires.
	roles map[string]any
	// code is the one authorization code the token endpoint accepts.
	code string
	// nonce is what the last authorization request carried, echoed back into
	// the ID token the way a provider echoes it.
	nonce string
	// nonceOverride replaces it, so a test can produce the ID token an attacker
	// replaying somebody else's login would present.
	nonceOverride string
	// lastForm is what the token endpoint was last called with, so a test can
	// assert that PKCE actually travelled.
	lastForm map[string]string
	// revoked records the tokens the node asked to have revoked.
	revoked []string
}

// rolesClaim is Zitadel's default spelling, and the one the config defaults to.
const rolesClaim = "urn:zitadel:iam:org:project:roles"

// newFakeProvider starts one. It is stopped by t.Cleanup.
func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}

	private, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("importing the signing key: %v", err)
	}

	if err := private.Set(jwk.KeyIDKey, "test-key"); err != nil {
		t.Fatalf("setting the key id: %v", err)
	}

	if err := private.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatalf("setting the algorithm: %v", err)
	}

	public, err := jwk.PublicKeyOf(private)
	if err != nil {
		t.Fatalf("deriving the public key: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(public); err != nil {
		t.Fatalf("building the key set: %v", err)
	}

	provider := &fakeProvider{
		server:        nil,
		key:           private,
		public:        set,
		roles:         map[string]any{"reader": map[string]any{"org-1": "alexandria.localhost"}},
		code:          "the-authorization-code",
		nonce:         "",
		nonceOverride: "",
		lastForm:      map[string]string{},
		revoked:       nil,
	}

	provider.server = httptest.NewServer(provider.routes())
	t.Cleanup(provider.server.Close)

	return provider
}

// URL is the issuer this provider speaks for.
func (p *fakeProvider) URL() string { return p.server.URL }

// routes is the provider's whole surface.
func (p *fakeProvider) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 p.server.URL,
			"authorization_endpoint": p.server.URL + "/oauth/v2/authorize",
			"token_endpoint":         p.server.URL + "/oauth/v2/token",
			"userinfo_endpoint":      p.server.URL + "/oidc/v1/userinfo",
			"jwks_uri":               p.server.URL + "/oauth/v2/keys",
			"introspection_endpoint": p.server.URL + "/oauth/v2/introspect",
			"revocation_endpoint":    p.server.URL + "/oauth/v2/revoke",
			"end_session_endpoint":   p.server.URL + "/oidc/v1/end_session",
		})
	})

	mux.HandleFunc("/oauth/v2/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, p.public)
	})

	mux.HandleFunc("/oauth/v2/authorize", p.authorize)

	mux.HandleFunc("/oauth/v2/token", p.token)

	mux.HandleFunc("/oauth/v2/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.revoked = append(p.revoked, r.PostFormValue("token"))
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

// authorize is where the browser lands. It authenticates nobody — that is the
// provider's business, not this node's — and returns the redirect a consenting
// user would have produced, remembering the nonce so the ID token can echo it.
func (p *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	p.nonce = query.Get("nonce")

	back, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)

		return
	}

	returned := url.Values{}
	returned.Set("code", p.code)
	returned.Set("state", query.Get("state"))
	back.RawQuery = returned.Encode()

	http.Redirect(w, r, back.String(), http.StatusFound)
}

// token is the token endpoint: it accepts the one code it was given, and the
// refresh token it handed out with it.
func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)

		return
	}

	p.lastForm = map[string]string{}
	for key := range r.PostForm {
		p.lastForm[key] = r.PostFormValue(key)
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		if r.PostFormValue("code") != p.code {
			writeError(w, "invalid_grant", "the authorization code is not valid")

			return
		}

		if r.PostFormValue("code_verifier") == "" {
			writeError(w, "invalid_request", "no pkce verifier")

			return
		}

	case "refresh_token":
		if r.PostFormValue("refresh_token") != "the-refresh-token" {
			writeError(w, "invalid_grant", "the refresh token is not valid")

			return
		}

	case "client_credentials":
		if r.PostFormValue("client_id") == "" && r.Header.Get("Authorization") == "" {
			writeError(w, "invalid_client", "no credentials")

			return
		}

	default:
		writeError(w, "unsupported_grant_type", "")

		return
	}

	signed := p.mint(nil)

	writeJSON(w, map[string]any{
		"access_token":  signed,
		"id_token":      signed,
		"refresh_token": "the-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "openid profile email offline_access",
	})
}

// mint signs an access token for the test's subject, valid for an hour.
func (p *fakeProvider) mint(overrides map[string]any) string {
	claims := map[string]any{
		"preferred_username":                    "someone@alexandria.localhost",
		"email":                                 "someone@alexandria.localhost",
		"name":                                  "Someone",
		"amr":                                   []string{"pwd"},
		"scope":                                 "openid profile email offline_access",
		"urn:zitadel:iam:user:resourceowner:id": "org-1",
		rolesClaim:                              p.roles,
	}

	if p.nonce != "" {
		claims["nonce"] = p.nonce
	}

	if p.nonceOverride != "" {
		claims["nonce"] = p.nonceOverride
	}

	for name, value := range overrides {
		claims[name] = value
	}

	builder := jwt.NewBuilder().
		Issuer(p.server.URL).
		Subject("user-1").
		Audience([]string{"alexandria"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))

	for name, value := range claims {
		builder = builder.Claim(name, value)
	}

	unsigned, err := builder.Build()
	if err != nil {
		panic(err)
	}

	signed, err := jwt.Sign(unsigned, jwt.WithKey(jwa.ES256(), p.key))
	if err != nil {
		panic(err)
	}

	return string(signed)
}

// writeJSON is the one response shape this provider speaks.
func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(body); err != nil {
		panic(err)
	}
}

// writeError renders the OAuth 2.0 error shape with the status the
// specification prescribes for a refused grant.
func writeError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	}); err != nil {
		panic(err)
	}
}

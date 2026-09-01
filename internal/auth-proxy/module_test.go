package authproxy_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authproxy "github.com/caparicio-esd/alexandria/internal/auth-proxy"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/identity"
	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/httpapi"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/gin-gonic/gin"
)

// protectedRoute is a stand-in for every route a bounded context mounts: the
// point is that it is behind the guard without knowing the guard exists.
const protectedRoute = httpapi.APIPrefix + "/ssi-auth/wallet/did"

// stubModule mounts one route and reports the caller the guard put on the
// request, which is how the tests assert that authentication actually reached
// the handler.
type stubModule struct{}

func (stubModule) Register(api *gin.RouterGroup) {
	api.GET("/ssi-auth/wallet/did", func(c *gin.Context) {
		principal := identity.FromContext(c.Request.Context())
		if principal == nil {
			c.JSON(http.StatusOK, gin.H{"subject": ""})

			return
		}

		c.JSON(http.StatusOK, gin.H{"subject": principal.Subject, "roles": principal.Roles})
	})
}

// newNode assembles the module against a fake provider and mounts it exactly as
// the composition root does, so what the tests exercise is the wiring the
// process actually runs.
func newNode(t *testing.T, provider *fakeProvider, tweak func(*config.Auth)) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	cfg := &config.Config{ //nolint:exhaustruct // only the auth section is under test
		Auth: config.Auth{ //nolint:exhaustruct // the rest of the fields default
			Enabled:                 true,
			Issuer:                  provider.URL(),
			ClientID:                "alexandria",
			ClientSecret:            "the-client-secret",
			Audiences:               []string{"alexandria"},
			Scopes:                  []string{"openid", "profile", "email", "offline_access"},
			RedirectURL:             "http://node.test" + httpapi.APIPrefix + "/auth/callback",
			AppURL:                  "http://node.test/",
			Introspect:              config.IntrospectFallback,
			RolesClaim:              rolesClaim,
			JWKSRefresh:             15 * time.Minute,
			HTTPTimeout:             5 * time.Second,
			StartupDiscoveryTimeout: 5 * time.Second,
			Session: config.SessionCookie{ //nolint:exhaustruct // a random key is minted
				Name:     "alexandria_session",
				Path:     "/",
				SameSite: "lax",
				TTL:      time.Hour,
			},
		},
	}

	if tweak != nil {
		tweak(&cfg.Auth)
	}

	module, err := authproxy.New(authproxy.Deps{
		Config: cfg,
		Logger: discardLogger(),
		Now:    time.Now,
	})
	if err != nil {
		t.Fatalf("assembling the module: %v", err)
	}

	t.Cleanup(func() { _ = module.Close() })

	if err := module.Start(t.Context()); err != nil {
		t.Fatalf("starting the module: %v", err)
	}

	// Start tolerates a provider that is down by retrying in the background;
	// these tests need the handshake to have landed before they assert.
	waitReady(t, module)

	engine := gin.New()
	httpapi.NewRouter(observability.NewHealth(), module, stubModule{}, module).Register(engine)

	return engine
}

// waitReady blocks until the module reports its provider reached.
func waitReady(t *testing.T, module *authproxy.Module) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	check := module.Checks()["identity_provider"]

	for time.Now().Before(deadline) {
		if err := check(t.Context()); err == nil {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the module never reached the provider")
}

// call issues a request against the node, carrying the given cookies.
func call(t *testing.T, engine *gin.Engine, method, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	return recorder
}

// TestTheApiIsClosed is the whole point of the context: a route a module
// mounted, with no credential, is refused — and refused as unauthenticated, so
// a client knows to log in rather than to retry.
func TestTheApiIsClosed(t *testing.T) {
	t.Parallel()

	engine := newNode(t, newFakeProvider(t), nil)

	recorder := call(t, engine, http.MethodGet, protectedRoute, nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET %s = %d, want 401", protectedRoute, recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 with no WWW-Authenticate leaves the client guessing what credential is missing")
	}
}

// TestLoginRoutesAnswerWithoutACredential: the routes that fix a 401 must not
// be behind it, or the API is one nobody can enter.
func TestLoginRoutesAnswerWithoutACredential(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	recorder := call(t, engine, http.MethodGet, httpapi.APIPrefix+"/auth/login?response=json", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /auth/login = %d, want 200", recorder.Code)
	}

	var body struct {
		AuthorizationURL string `json:"authorization_url"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}

	target, err := url.Parse(body.AuthorizationURL)
	if err != nil {
		t.Fatalf("the authorization url does not parse: %v", err)
	}

	if !strings.HasPrefix(body.AuthorizationURL, provider.URL()) {
		t.Errorf("the login points at %q, not at the provider", body.AuthorizationURL)
	}

	query := target.Query()
	for _, parameter := range []string{"state", "nonce", "code_challenge", "redirect_uri"} {
		if query.Get(parameter) == "" {
			t.Errorf("the authorization request carries no %s", parameter)
		}
	}

	// S256 and nothing else: a "plain" challenge is a challenge in name only.
	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
}

// TestTheWholeFlow walks a browser through login, callback and a protected
// call, which is the path every human takes.
func TestTheWholeFlow(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	started := call(t, engine, http.MethodGet,
		httpapi.APIPrefix+"/auth/login?response=json&return_to=/console", nil)

	flowCookies := started.Result().Cookies()
	if len(flowCookies) == 0 {
		t.Fatal("the login set no flow cookie, so the callback has nothing to check against")
	}

	var body struct {
		AuthorizationURL string `json:"authorization_url"`
	}

	if err := json.Unmarshal(started.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the login response: %v", err)
	}

	callback := authorize(t, body.AuthorizationURL)

	completed := call(t, engine, http.MethodGet, callback, flowCookies)
	if completed.Code != http.StatusFound {
		t.Fatalf("the callback answered %d, want a redirect: %s", completed.Code, completed.Body.String())
	}

	if location := completed.Header().Get("Location"); location != "/console" {
		t.Errorf("the callback sent the browser to %q, want the requested /console", location)
	}

	// The verifier has to have travelled with the exchange, or the code was
	// usable by anything that intercepted the redirect.
	if provider.lastForm["code_verifier"] == "" {
		t.Error("the exchange carried no pkce verifier")
	}

	session := sessionCookie(t, completed.Result().Cookies())

	protected := call(t, engine, http.MethodGet, protectedRoute, []*http.Cookie{session})
	if protected.Code != http.StatusOK {
		t.Fatalf("GET %s with a session = %d, want 200: %s",
			protectedRoute, protected.Code, protected.Body.String())
	}

	var handled struct {
		Subject string   `json:"subject"`
		Roles   []string `json:"roles"`
	}

	if err := json.Unmarshal(protected.Body.Bytes(), &handled); err != nil {
		t.Fatalf("decoding the handler's response: %v", err)
	}

	if handled.Subject != "user-1" {
		t.Errorf("the handler saw subject %q, want user-1", handled.Subject)
	}

	if len(handled.Roles) != 1 || handled.Roles[0] != "reader" {
		t.Errorf("the handler saw roles %v, want [reader]", handled.Roles)
	}
}

// TestTheSessionRouteDescribesTheCallerWithoutLeakingTokens: a frontend polls
// this, and what it must never receive is a bearer credential.
func TestTheSessionRouteDescribesTheCallerWithoutLeakingTokens(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)
	session := login(t, engine)

	recorder := call(t, engine, http.MethodGet, httpapi.APIPrefix+"/auth/session", []*http.Cookie{session})
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /auth/session = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if strings.Contains(body, "eyJ") || strings.Contains(body, "the-refresh-token") {
		t.Errorf("the session document carries a token: %s", body)
	}

	if !strings.Contains(body, "user-1") {
		t.Errorf("the session document does not name the caller: %s", body)
	}
}

// TestLogoutRevokesAtTheProvider: dropping the cookie alone leaves a refresh
// token alive for its full lifetime, which is a session the user believes they
// ended.
func TestLogoutRevokesAtTheProvider(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)
	session := login(t, engine)

	recorder := call(t, engine, http.MethodPost,
		httpapi.APIPrefix+"/auth/logout?response=json", []*http.Cookie{session})
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /auth/logout = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	if len(provider.revoked) != 1 || provider.revoked[0] != "the-refresh-token" {
		t.Errorf("the provider was asked to revoke %v, want the refresh token", provider.revoked)
	}

	cleared := false

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "alexandria_session" && cookie.MaxAge < 0 {
			cleared = true
		}
	}

	if !cleared {
		t.Error("the logout did not clear the session cookie")
	}
}

// TestARequiredRoleIsEnforced: authentication is not authorization, and the
// difference has to be a 403 rather than a 401 — logging in again would not
// help.
func TestARequiredRoleIsEnforced(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, func(cfg *config.Auth) {
		cfg.RequiredRoles = []string{"operator"}
	})

	session := login(t, engine)

	recorder := call(t, engine, http.MethodGet, protectedRoute, []*http.Cookie{session})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a caller without the required role got %d, want 403", recorder.Code)
	}
}

// TestABearerTokenIsAccepted: a peer node or a CLI has no cookie jar, and must
// be able to present the token itself.
func TestABearerTokenIsAccepted(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, protectedRoute, nil)
	request.Header.Set("Authorization", "Bearer "+provider.mint(nil))

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("a bearer token got %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
}

// TestATokenForAnotherAudienceIsRefused: the audience is what keeps a token
// minted for a different application of the same provider from opening this
// API.
func TestATokenForAnotherAudienceIsRefused(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, protectedRoute, nil)
	request.Header.Set("Authorization", "Bearer "+provider.mint(map[string]any{"aud": []string{"somebody-else"}}))

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("a token for another audience got %d, want 401", recorder.Code)
	}
}

// TestAForgedTokenIsRefused: a token this provider did not sign must not open
// anything, however well-formed it is.
func TestAForgedTokenIsRefused(t *testing.T) {
	t.Parallel()

	engine := newNode(t, newFakeProvider(t), nil)
	// Signed by a provider of its own, with its own key.
	forged := newFakeProvider(t).mint(nil)

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, protectedRoute, nil)
	request.Header.Set("Authorization", "Bearer "+forged)

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("a token signed by somebody else got %d, want 401", recorder.Code)
	}
}

// TestTheCallbackChecksTheState: the state parameter is the only thing standing
// between this node and a cross-site login.
func TestTheCallbackChecksTheState(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	started := call(t, engine, http.MethodGet, httpapi.APIPrefix+"/auth/login?response=json", nil)

	recorder := call(t, engine, http.MethodGet,
		httpapi.APIPrefix+"/auth/callback?code="+provider.code+"&state=somebody-elses-state",
		started.Result().Cookies())

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a callback with a foreign state got %d, want 400", recorder.Code)
	}
}

// TestTheCallbackChecksTheNonce: the access token says the provider
// authenticated somebody, and only the nonce says it was this login, in this
// browser. An ID token minted for another session and replayed here must not
// produce a session.
func TestTheCallbackChecksTheNonce(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	started := call(t, engine, http.MethodGet, httpapi.APIPrefix+"/auth/login?response=json", nil)

	var body struct {
		AuthorizationURL string `json:"authorization_url"`
	}

	if err := json.Unmarshal(started.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the login response: %v", err)
	}

	callback := authorize(t, body.AuthorizationURL)
	provider.nonceOverride = "somebody-elses-nonce"

	completed := call(t, engine, http.MethodGet, callback, started.Result().Cookies())
	if completed.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed id token got %d, want 401", completed.Code)
	}

	for _, cookie := range completed.Result().Cookies() {
		if cookie.Name == "alexandria_session" && cookie.Value != "" {
			t.Error("the callback sealed a session anyway")
		}
	}
}

// TestAnOffOriginReturnIsIgnored: the return_to parameter arrives in a link, so
// an unvalidated one turns the login into a phishing hop.
func TestAnOffOriginReturnIsIgnored(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	started := call(t, engine, http.MethodGet,
		httpapi.APIPrefix+"/auth/login?response=json&return_to=https://evil.example/steal", nil)

	var body struct {
		AuthorizationURL string `json:"authorization_url"`
	}

	if err := json.Unmarshal(started.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the login response: %v", err)
	}

	completed := call(t, engine, http.MethodGet,
		authorize(t, body.AuthorizationURL), started.Result().Cookies())

	if location := completed.Header().Get("Location"); location != "http://node.test/" {
		t.Errorf("the callback redirected to %q, want the configured app url", location)
	}
}

// TestTheMachineGrantIsProxied: a service account authenticates through this
// node like everything else, and never learns where the provider lives.
func TestTheMachineGrantIsProxied(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	engine := newNode(t, provider, nil)

	form := strings.NewReader(url.Values{
		"client_id":     {"a-service-account"},
		"client_secret": {"its-secret"},
	}.Encode())

	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		httpapi.APIPrefix+"/auth/token", form)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /auth/token = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the token response: %v", err)
	}

	if body["access_token"] == "" || body["access_token"] == nil {
		t.Error("the response carries no access token")
	}

	// A machine holding its own credentials can ask again; handing it a
	// long-lived one over an API is one more thing to leak.
	if _, found := body["refresh_token"]; found {
		t.Error("the machine grant handed back a refresh token")
	}
}

// TestTheProbesStayOutsideTheGuard: a kubelet presents no credential, and a
// node that answers 401 to its liveness probe is a node that gets restarted
// forever.
func TestTheProbesStayOutsideTheGuard(t *testing.T) {
	t.Parallel()

	engine := newNode(t, newFakeProvider(t), nil)

	if recorder := call(t, engine, http.MethodGet, "/healthz", nil); recorder.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", recorder.Code)
	}
}

// authorize follows the authorization URL to the provider, which is the step a
// browser takes and this node never sees, and returns the callback the provider
// redirected back to — path and query, as the node will receive it.
func authorize(t *testing.T, target string) string {
	t.Helper()

	client := &http.Client{ //nolint:exhaustruct // only the redirect policy matters
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("building the authorization request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("calling the provider: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	back, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the provider redirected somewhere unparseable: %v", err)
	}

	return back.Path + "?" + back.RawQuery
}

// login walks the flow and returns the session cookie it produced.
func login(t *testing.T, engine *gin.Engine) *http.Cookie {
	t.Helper()

	started := call(t, engine, http.MethodGet, httpapi.APIPrefix+"/auth/login?response=json", nil)

	var body struct {
		AuthorizationURL string `json:"authorization_url"`
	}

	if err := json.Unmarshal(started.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the login response: %v", err)
	}

	completed := call(t, engine, http.MethodGet,
		authorize(t, body.AuthorizationURL), started.Result().Cookies())
	if completed.Code != http.StatusFound {
		t.Fatalf("the callback answered %d, want a redirect: %s", completed.Code, completed.Body.String())
	}

	return sessionCookie(t, completed.Result().Cookies())
}

// sessionCookie picks the session out of a response's cookies.
func sessionCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name == "alexandria_session" && cookie.Value != "" {
			return cookie
		}
	}

	t.Fatal("the response set no session cookie")

	return nil
}

// discardLogger is the process logger, silenced: these tests assert on
// responses, and a module that logs its retries would bury them.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

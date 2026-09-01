package session_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/session"
	"github.com/caparicio-esd/alexandria/internal/config"
)

// newManager builds a manager over a fresh random key.
func newManager(t *testing.T) *session.Manager {
	t.Helper()

	key, err := session.RandomKey()
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	manager, err := session.NewManager(key, config.SessionCookie{
		Name:     "alexandria_session",
		Domain:   "",
		Path:     "/",
		Secure:   false,
		SameSite: "lax",
		TTL:      time.Hour,
		Key:      "",
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}

	return manager
}

// replay moves the cookies a response set onto a new request, which is what a
// browser does between two calls.
func replay(t *testing.T, recorder *httptest.ResponseRecorder) *http.Request {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/anything", nil)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}

	return request
}

// TestSessionRoundTrips is the property the whole proxy rests on: what goes
// into the cookie comes back out, and only here.
func TestSessionRoundTrips(t *testing.T) {
	t.Parallel()

	manager := newManager(t)
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)

	state := session.State{
		Subject:      "user-1",
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "identity",
		Scope:        "openid profile",
		TokenExpiry:  now.Add(time.Minute),
		IssuedAt:     now,
		Expiry:       time.Time{},
	}

	recorder := httptest.NewRecorder()
	if err := manager.Save(recorder, state, now); err != nil {
		t.Fatalf("saving: %v", err)
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("saved %d cookies, want 1", len(cookies))
	}

	// The tokens must not be readable off the wire: that is the difference
	// between a proxy and a token handed to the browser.
	if strings.Contains(cookies[0].Value, "access") || strings.Contains(cookies[0].Value, "refresh") {
		t.Error("the cookie carries a token in the clear")
	}

	if !cookies[0].HttpOnly {
		t.Error("the session cookie is readable from script")
	}

	loaded, err := manager.Load(replay(t, recorder), now)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	if loaded.AccessToken != state.AccessToken || loaded.RefreshToken != state.RefreshToken {
		t.Errorf("loaded %+v, want the tokens that went in", loaded)
	}

	if loaded.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", loaded.Subject)
	}
}

// TestTamperedCookieIsRefused: authentication is the point of GCM here. A
// cookie a client edited must not open, whatever it was edited into.
func TestTamperedCookieIsRefused(t *testing.T) {
	t.Parallel()

	manager := newManager(t)
	now := time.Now()

	recorder := httptest.NewRecorder()
	if err := manager.Save(recorder, session.State{ //nolint:exhaustruct // only the subject matters here
		Subject:     "user-1",
		AccessToken: "access",
	}, now); err != nil {
		t.Fatalf("saving: %v", err)
	}

	cookie := recorder.Result().Cookies()[0]
	// Flip one character in the middle of the ciphertext. The middle rather
	// than the end: the last base64 character of an unpadded encoding carries
	// spare bits that decode to the same bytes, so editing it proves nothing.
	middle := len(cookie.Value) / 2
	replacement := byte('A')

	if cookie.Value[middle] == replacement {
		replacement = 'B'
	}

	edited := cookie.Value[:middle] + string(replacement) + cookie.Value[middle+1:]

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/anything", nil)
	request.AddCookie(&http.Cookie{Name: cookie.Name, Value: edited}) //nolint:exhaustruct // a request cookie is name and value

	if _, err := manager.Load(request, now); !errors.Is(err, session.ErrInvalidSession) {
		t.Errorf("loading a tampered cookie = %v, want ErrInvalidSession", err)
	}
}

// TestExpiredSessionIsRefused: the deadline inside the sealed payload is what
// bounds a stolen cookie, since the browser holds the Max-Age and an attacker
// simply would not send it.
func TestExpiredSessionIsRefused(t *testing.T) {
	t.Parallel()

	manager := newManager(t)
	now := time.Now()

	recorder := httptest.NewRecorder()
	if err := manager.Save(recorder, session.State{ //nolint:exhaustruct // only the subject matters here
		Subject: "user-1",
	}, now); err != nil {
		t.Fatalf("saving: %v", err)
	}

	if _, err := manager.Load(replay(t, recorder), now.Add(2*time.Hour)); !errors.Is(err, session.ErrInvalidSession) {
		t.Errorf("loading past the ttl = %v, want ErrInvalidSession", err)
	}
}

// TestNoCookieIsNotAFailure: an anonymous caller is an ordinary state, and it
// has to be distinguishable from a broken cookie — one deserves a login, the
// other deserves the cookie cleared.
func TestNoCookieIsNotAFailure(t *testing.T) {
	t.Parallel()

	manager := newManager(t)

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/anything", nil)
	if _, err := manager.Load(request, time.Now()); !errors.Is(err, session.ErrNoSession) {
		t.Errorf("loading without a cookie = %v, want ErrNoSession", err)
	}
}

// TestFlowCookieIsSeparate: the login in progress must not be readable as a
// session, or a half-finished login would look like an authenticated caller.
func TestFlowCookieIsSeparate(t *testing.T) {
	t.Parallel()

	manager := newManager(t)
	now := time.Now()

	recorder := httptest.NewRecorder()
	if err := manager.SaveFlow(recorder, session.Flow{ //nolint:exhaustruct // Expiry is stamped by SaveFlow
		State:    "state",
		Nonce:    "nonce",
		Verifier: "verifier",
		Return:   "/console",
	}, now); err != nil {
		t.Fatalf("saving the flow: %v", err)
	}

	request := replay(t, recorder)

	if _, err := manager.Load(request, now); !errors.Is(err, session.ErrNoSession) {
		t.Errorf("the flow cookie loaded as a session: %v", err)
	}

	flow, err := manager.LoadFlow(request, now)
	if err != nil {
		t.Fatalf("loading the flow: %v", err)
	}

	if flow.Verifier != "verifier" || flow.Return != "/console" {
		t.Errorf("flow = %+v, want the values that went in", flow)
	}

	if _, err := manager.LoadFlow(request, now.Add(time.Hour)); !errors.Is(err, session.ErrInvalidSession) {
		t.Errorf("an abandoned login stayed valid: %v", err)
	}
}

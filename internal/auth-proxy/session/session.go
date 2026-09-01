// Package session keeps the browser's half of the proxy: a sealed cookie.
//
// The tokens never leave this process in readable form. The cookie carries them
// encrypted with AES-256-GCM under a key only the node holds, marked HttpOnly
// so no script can read it, and stamped with its own expiry so a copy taken
// today is worthless tomorrow. A browser that has the cookie has a session; it
// does not have a bearer token, which is the entire reason the proxy exists.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
)

var (
	// ErrNoSession reports that the request carried no cookie. It is the
	// ordinary state of an anonymous caller, not a failure.
	ErrNoSession = errors.New("no session")
	// ErrInvalidSession reports a cookie that will not open: tampered with,
	// sealed under a previous key, or past its own expiry. Every one of them is
	// answered the same way — the cookie is cleared and the caller logs in
	// again — so they are one error.
	ErrInvalidSession = errors.New("session is not valid")
)

// State is what a session holds between requests.
//
// The tokens are in here rather than in a server-side store on purpose: this
// node is one of many in a dataspace and has no session affinity, and a shared
// store would be one more thing to run for state the browser can carry itself.
// The trade is that a logout has to revoke at the provider, which it does.
type State struct {
	Subject      string    `json:"sub"`
	AccessToken  string    `json:"at"`
	RefreshToken string    `json:"rt,omitempty"`
	IDToken      string    `json:"it,omitempty"`
	Scope        string    `json:"scp,omitempty"`
	TokenExpiry  time.Time `json:"tex"`
	IssuedAt     time.Time `json:"iat"`
	// Expiry is the session's own deadline, checked on open. It is inside the
	// sealed payload rather than trusted from the cookie's Max-Age, which the
	// browser holds and an attacker replaying a stolen cookie would simply not
	// send.
	Expiry time.Time `json:"exp"`
}

// Flow is the short-lived state of a login in progress: what the callback needs
// to prove that the code it was handed answers the request this node made.
type Flow struct {
	State    string    `json:"st"`
	Nonce    string    `json:"nc"`
	Verifier string    `json:"cv"`
	Return   string    `json:"rt,omitempty"`
	Expiry   time.Time `json:"exp"`
}

// Manager seals and opens the cookies. One key serves both, since both are
// this node talking to itself.
type Manager struct {
	aead     cipher.AEAD
	cookie   config.SessionCookie
	flowName string
	ttl      time.Duration
	flowTTL  time.Duration
}

// flowTTL bounds a login in progress. It is long enough for someone to find
// their password manager and short enough that an abandoned attempt is not
// still valid after lunch.
const flowTTL = 10 * time.Minute

// NewManager builds the sealer from a 32-byte key.
func NewManager(key []byte, cookie config.SessionCookie) (*Manager, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("session: building the cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("session: building the aead: %w", err)
	}

	return &Manager{
		aead:     aead,
		cookie:   cookie,
		flowName: cookie.Name + "_flow",
		ttl:      cookie.TTL,
		flowTTL:  flowTTL,
	}, nil
}

// RandomKey mints a sealing key, for a development run where the operator set
// none. Every restart invalidates every session, which is the point: a process
// that generates its own key must not be one anybody depends on.
func RandomKey() ([]byte, error) {
	key := make([]byte, config.SessionKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("session: generating a sealing key: %w", err)
	}

	return key, nil
}

// TTL is how long a sealed session lives.
func (m *Manager) TTL() time.Duration { return m.ttl }

// Save seals the state into the response's session cookie.
func (m *Manager) Save(w http.ResponseWriter, state State, now time.Time) error {
	state.Expiry = now.Add(m.ttl)

	sealed, err := m.seal(state)
	if err != nil {
		return err
	}

	http.SetCookie(w, m.newCookie(m.cookie.Name, sealed, int(m.ttl.Seconds())))

	return nil
}

// Load opens the session cookie on a request.
func (m *Manager) Load(r *http.Request, now time.Time) (State, error) {
	var state State

	cookie, err := r.Cookie(m.cookie.Name)
	if err != nil {
		return state, ErrNoSession
	}

	if err := m.open(cookie.Value, &state); err != nil {
		return State{}, err
	}

	if !state.Expiry.IsZero() && now.After(state.Expiry) {
		return State{}, fmt.Errorf("session: expired: %w", ErrInvalidSession)
	}

	return state, nil
}

// Clear removes the session cookie. The attributes have to match the ones it
// was set with, or the browser keeps the original alongside the deletion.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, m.newCookie(m.cookie.Name, "", -1))
}

// SaveFlow seals the login in progress.
func (m *Manager) SaveFlow(w http.ResponseWriter, flow Flow, now time.Time) error {
	flow.Expiry = now.Add(m.flowTTL)

	sealed, err := m.seal(flow)
	if err != nil {
		return err
	}

	http.SetCookie(w, m.newCookie(m.flowName, sealed, int(m.flowTTL.Seconds())))

	return nil
}

// LoadFlow opens the login in progress.
func (m *Manager) LoadFlow(r *http.Request, now time.Time) (Flow, error) {
	var flow Flow

	cookie, err := r.Cookie(m.flowName)
	if err != nil {
		return flow, ErrNoSession
	}

	if err := m.open(cookie.Value, &flow); err != nil {
		return Flow{}, err
	}

	if now.After(flow.Expiry) {
		return Flow{}, fmt.Errorf("session: login attempt expired: %w", ErrInvalidSession)
	}

	return flow, nil
}

// ClearFlow removes the login-in-progress cookie, which the callback does the
// moment it has used it: it is single-use by design.
func (m *Manager) ClearFlow(w http.ResponseWriter) {
	http.SetCookie(w, m.newCookie(m.flowName, "", -1))
}

// newCookie applies the configured attributes to every cookie this package
// sets, so none of them can drift out of step with the others.
func (m *Manager) newCookie(name, value string, maxAge int) *http.Cookie {
	// gosec cannot see that Secure comes from configuration, which is validated
	// to be true in production; HttpOnly and SameSite are set unconditionally
	// right here.
	return &http.Cookie{ //nolint:exhaustruct,gosec // the zero fields are the defaults net/http wants
		Name:     name,
		Value:    value,
		Path:     m.cookie.CookiePath(),
		Domain:   m.cookie.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   m.cookie.Secure,
		SameSite: m.cookie.SameSitePolicy(),
	}
}

// seal encrypts a payload into a cookie value: nonce, then ciphertext, the
// whole thing base64url-encoded so it survives a Set-Cookie header.
func (m *Manager) seal(payload any) (string, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("session: encoding the payload: %w", err)
	}

	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("session: generating a nonce: %w", err)
	}

	sealed := m.aead.Seal(nonce, nonce, plain, nil)

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts a cookie value onto out.
//
// Every failure is reported as ErrInvalidSession with no detail: telling a
// caller whether their cookie failed to decode, failed to authenticate or
// failed to parse is telling an attacker which half of their guess was right.
func (m *Manager) open(value string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("session: %w", ErrInvalidSession)
	}

	if len(raw) < m.aead.NonceSize() {
		return fmt.Errorf("session: %w", ErrInvalidSession)
	}

	nonce, ciphertext := raw[:m.aead.NonceSize()], raw[m.aead.NonceSize():]

	plain, err := m.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("session: %w", ErrInvalidSession)
	}

	if err := json.Unmarshal(plain, out); err != nil {
		return fmt.Errorf("session: %w", ErrInvalidSession)
	}

	return nil
}

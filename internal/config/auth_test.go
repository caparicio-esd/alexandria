package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/config"
)

// enabledAuth is a valid production-shaped section, which each case then breaks
// in exactly one way.
func enabledAuth() config.Auth {
	return config.Auth{ //nolint:exhaustruct // the optional fields are the point of the defaults
		Enabled:      true,
		Issuer:       "https://auth.example.org",
		ClientID:     "alexandria",
		ClientSecret: "secret",
		RedirectURL:  "https://node.example.org/api/v1/auth/callback",
		AppURL:       "https://node.example.org/",
		Introspect:   config.IntrospectFallback,
		JWKSRefresh:  900_000_000_000,
		HTTPTimeout:  10_000_000_000,
		Session: config.SessionCookie{ //nolint:exhaustruct // no domain, host-only
			Name:     "alexandria_session",
			Path:     "/",
			Secure:   true,
			SameSite: "lax",
			TTL:      43_200_000_000_000,
			Key:      strings.Repeat("ab", 32),
		},
	}
}

// TestDisabledAuthNeedsNothing: a node with no identity provider must still
// load, or every development checkout has to configure one.
func TestDisabledAuthNeedsNothing(t *testing.T) {
	t.Parallel()

	empty := config.Auth{} //nolint:exhaustruct // the zero value is exactly what is under test
	if err := empty.Validate(false); err != nil {
		t.Errorf("an empty disabled section was refused: %v", err)
	}
}

// TestEnabledAuthIsAccepted pins that the shape a deployment writes is the
// shape the loader takes.
func TestEnabledAuthIsAccepted(t *testing.T) {
	t.Parallel()

	auth := enabledAuth()
	if err := auth.Validate(true); err != nil {
		t.Errorf("a complete section was refused: %v", err)
	}
}

// TestProductionRulesAreTighter: the settings that are merely inconvenient on a
// workstation are outages waiting to happen in production, and the loader is
// where that difference is enforced rather than in a runbook.
func TestProductionRulesAreTighter(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*config.Auth){
		"a cookie in the clear":  func(a *config.Auth) { a.Session.Secure = false },
		"no sealing key":         func(a *config.Auth) { a.Session.Key = "" },
		"no client secret":       func(a *config.Auth) { a.ClientSecret = "" },
		"an unknown same-site":   func(a *config.Auth) { a.Session.SameSite = "sometimes" },
		"an unknown introspect":  func(a *config.Auth) { a.Introspect = "maybe" },
		"a relative issuer":      func(a *config.Auth) { a.Issuer = "auth.example.org" },
		"a short sealing key":    func(a *config.Auth) { a.Session.Key = "abcd" },
		"no redirect url":        func(a *config.Auth) { a.RedirectURL = "" },
		"a zero jwks refresh":    func(a *config.Auth) { a.JWKSRefresh = 0 },
		"same-site none in http": func(a *config.Auth) { a.Session.SameSite = "none"; a.Session.Secure = false },
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			auth := enabledAuth()
			breakIt(&auth)

			err := auth.Validate(true)
			if err == nil {
				t.Fatal("the section was accepted")
			}

			if !errors.Is(err, config.ErrInvalid) {
				t.Errorf("error %v does not wrap ErrInvalid, so a caller cannot tell it from a missing file", err)
			}
		})
	}
}

// TestASealingKeyIsAcceptedInEitherSpelling: the two commands an operator
// reaches for print different encodings, and rejecting one is a papercut with
// no upside.
func TestASealingKeyIsAcceptedInEitherSpelling(t *testing.T) {
	t.Parallel()

	for name, key := range map[string]string{
		"hex":    strings.Repeat("ab", 32),
		"base64": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cookie := config.SessionCookie{Key: key} //nolint:exhaustruct // SealingKey reads the key alone

			raw, err := cookie.SealingKey()
			if err != nil {
				t.Fatalf("decoding: %v", err)
			}

			if len(raw) != config.SessionKeyBytes {
				t.Errorf("decoded %d bytes, want %d", len(raw), config.SessionKeyBytes)
			}
		})
	}
}

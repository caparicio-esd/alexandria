// Package authproxy assembles the authentication bounded context.
//
// It is a proxy in the strict sense: nothing outside this node ever addresses
// the identity provider. A browser navigates to /api/v1/auth/login and is
// walked through the authorization code flow by this process, which holds the
// client secret, terminates the callback, and hands back a sealed HttpOnly
// cookie instead of a token. A service account posts its credentials to
// /api/v1/auth/token and gets an access token without ever learning where
// Zitadel lives. Everything else under /api/v1 passes through the guard.
//
// The consequence worth stating: the provider's address is deployment
// configuration on this side only. Moving Zitadel, putting it behind a private
// network, or replacing it with another OpenID Provider changes one YAML block
// and nothing a client ever sees.
package authproxy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/caparicio-esd/alexandria/internal/auth-proxy/oidc"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/rest"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/session"
	"github.com/caparicio-esd/alexandria/internal/auth-proxy/token"
	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/gin-gonic/gin"
)

// Discovery backoff, on the same reasoning as the wallet handshake: the common
// case is a provider seconds away from ready, and the cap keeps a long outage
// from stretching the gap out to something useless.
const (
	discoverFirstBackoff = 500 * time.Millisecond
	discoverMaxBackoff   = 10 * time.Second
)

// Name is how this context identifies itself in logs, probes and reports.
const Name = "auth-proxy"

// Deps is everything the context needs from outside itself.
type Deps struct {
	// Config is the whole document; the module picks out its own section.
	Config *config.Config
	// Logger is the process logger, which the module scopes to itself.
	Logger *slog.Logger
	// Now is the clock, injected so session expiry stays deterministic under
	// test.
	Now func() time.Time
}

// Module is the assembled context.
type Module struct {
	client   *oidc.Client
	verifier *token.Verifier
	router   *rest.AuthRouter
	logger   *slog.Logger
	budget   time.Duration
	issuer   string

	// background owns the goroutine that keeps retrying discovery, so Close can
	// wait for it instead of leaving it writing to a logger the process
	// believes it has finished with.
	background sync.WaitGroup
	cancel     context.CancelFunc
}

// New assembles the context.
//
// It contacts nothing: the provider is reached in Start, which tolerates it
// being down. A node that refuses to boot because its identity provider is
// slow to come up is a node that turns one restart into two outages.
func New(deps Deps) (*Module, error) {
	if deps.Config == nil {
		return nil, fmt.Errorf("%s: no configuration given", Name)
	}

	cfg := deps.Config.Auth
	logger := observability.Scoped(deps.Logger, observability.ModuleAuthProxy, "")

	client, err := oidc.New(cfg.Issuer, cfg.ProviderURL(), cfg.ClientID, cfg.ClientSecret,
		cfg.HTTPTimeout, observability.Scoped(deps.Logger, observability.ModuleAuthProxy, "oidc"))
	if err != nil {
		return nil, fmt.Errorf("%s: building the provider client: %w", Name, err)
	}

	key, err := sealingKey(cfg.Session, logger)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}

	sessions, err := session.NewManager(key, cfg.Session)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}

	verifier := token.New(client, cfg, observability.Scoped(deps.Logger, observability.ModuleAuthProxy, "token"))

	now := deps.Now
	if now == nil {
		now = time.Now
	}

	return &Module{ //nolint:exhaustruct // background and cancel belong to Start
		client:   client,
		verifier: verifier,
		router: rest.NewAuthRouter(rest.Deps{
			Client:   client,
			Sessions: sessions,
			Verifier: verifier,
			Config:   cfg,
			Now:      now,
			Logger:   observability.Scoped(deps.Logger, observability.ModuleAuthProxy, "rest"),
		}),
		logger: logger,
		budget: cfg.StartupDiscoveryTimeout,
		issuer: cfg.Issuer,
	}, nil
}

// sealingKey resolves the key that seals the session cookie, minting a random
// one when the deployment configured none. Validation has already refused an
// empty key in production, so reaching the fallback means a workstation.
func sealingKey(cfg config.SessionCookie, logger *slog.Logger) ([]byte, error) {
	if cfg.Key != "" {
		key, err := cfg.SealingKey()
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	key, err := session.RandomKey()
	if err != nil {
		return nil, err
	}

	logger.Warn("no session key configured: sealing with a random one, " +
		"so every session ends when this process restarts")

	return key, nil
}

// Name identifies the context.
func (m *Module) Name() string { return Name }

// Register mounts the routes that describe an authenticated caller. They sit
// behind the guard like every other route under the API prefix.
func (m *Module) Register(api *gin.RouterGroup) { m.router.Register(api) }

// Public mounts the routes that must answer before there is anything to
// authenticate with. It satisfies httpapi.Guard, which calls it on a group
// taken before the guard is installed.
func (m *Module) Public(api *gin.RouterGroup) { m.router.RegisterPublic(api) }

// Protect is the middleware every other route under the API prefix passes
// through. It satisfies httpapi.Guard.
func (m *Module) Protect() gin.HandlerFunc { return m.router.Protect() }

// Checks are the context's contributions to readiness.
//
// A node whose provider has not been reached cannot authenticate anybody, and
// with the whole API protected that means it cannot serve: it says so here
// rather than answering 503 to a load balancer that thinks it is healthy.
func (m *Module) Checks() map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"identity_provider": func(context.Context) error {
			if !m.verifier.Ready() {
				return fmt.Errorf("identity provider not reached: %w", observability.ErrNotReady)
			}

			return nil
		},
	}
}

// Describe reports the issuer for the startup report.
func (m *Module) Describe() (string, bool) {
	if _, ok := m.client.Metadata(); !ok {
		return m.issuer + " (not reached)", true
	}

	return m.issuer, true
}

// Start reads the provider's configuration and starts following its signing
// keys.
//
// It mirrors the wallet handshake: a short budget catches the common case, and
// past it the node comes up anyway, reports itself not ready, and keeps
// retrying — with the guard answering 503 rather than 401, so no client throws
// away a good credential because the provider was slow.
func (m *Module) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	budgeted, cancel := context.WithTimeout(ctx, m.budget)
	defer cancel()

	if err := m.discover(budgeted, true); err == nil {
		return nil
	}

	m.logger.WarnContext(ctx, "identity provider not reached within the startup budget; retrying in the background",
		"issuer", m.issuer, "budget", m.budget.String())

	m.background.Add(1)

	go func() {
		defer m.background.Done()

		if err := m.discover(ctx, false); err != nil {
			// The only way out of the loop besides success is the process
			// shutting down, so this is expected on the way out.
			m.logger.InfoContext(ctx, "provider discovery abandoned", "err", err)
		}
	}()

	return nil
}

// discover retries the handshake until it succeeds or the context ends.
func (m *Module) discover(ctx context.Context, announce bool) error {
	backoff := discoverFirstBackoff

	for attempt := 1; ; attempt++ {
		err := m.handshake(ctx)
		if err == nil {
			return nil
		}

		// The budget and the shutdown signal both land here as a cancelled
		// context, and neither is worth another attempt.
		if ctx.Err() != nil {
			return fmt.Errorf("discovering the identity provider after %d attempts: %w", attempt, err)
		}

		if announce {
			m.logger.WarnContext(ctx, "identity provider not ready",
				"attempt", attempt, "retry_in", backoff.String(), "err", err)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("discovering the identity provider after %d attempts: %w", attempt, err)
		case <-time.After(backoff):
		}

		// No jitter: there is one client here, so there is no herd to spread.
		backoff = min(backoff*2, discoverMaxBackoff)
	}
}

// handshake is one attempt: read the document, then bind to the keys it names.
func (m *Module) handshake(ctx context.Context) error {
	meta, err := m.client.Discover(ctx)
	if err != nil {
		return err
	}

	// The cache outlives this context — it refreshes on a schedule of its own —
	// so it is bound to the module's lifetime, not to the attempt's.
	if err := m.verifier.Bind(context.WithoutCancel(ctx), meta.JWKSURI); err != nil {
		return err
	}

	m.logger.InfoContext(ctx, "identity provider ready", "issuer", meta.Issuer)

	return nil
}

// Close stops the background handshake, waits for it, and releases what the
// context owns.
func (m *Module) Close() error {
	if m.cancel != nil {
		m.cancel()
	}

	m.background.Wait()

	ctx := context.Background()

	if err := m.verifier.Close(ctx); err != nil {
		return fmt.Errorf("%s: %w", Name, err)
	}

	if err := m.client.Close(); err != nil {
		return fmt.Errorf("%s: closing the provider client: %w", Name, err)
	}

	return nil
}

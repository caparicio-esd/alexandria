// Package ssiauth assembles the identity and authorization bounded context.
//
// It is the context's own composition: given configuration and the shared
// infrastructure, it builds its adapters, wires them to its use cases through
// the ports the domain declares, and hands back one thing the process can mount
// and supervise. Nothing outside this package needs to know that the wallet is
// reached over HTTP, or that its HTTP surface is called rest.
//
// This is a constructor, not a container. Dependencies arrive as parameters and
// travel inwards; the module never reaches for a global, and the domain
// underneath it still imports no framework.
package ssiauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/fafnir"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
)

// Wallet handshake backoff. The first pause is short because the common case is
// a wallet seconds away from ready; the cap keeps a long outage from stretching
// the gap out to something useless.
const (
	linkFirstBackoff = 500 * time.Millisecond
	linkMaxBackoff   = 10 * time.Second
)

// Name is how this context identifies itself in logs, probes and reports.
const Name = "ssi-auth"

// Deps is everything the context needs from outside itself.
//
// A struct rather than a parameter list: it is the seam that grows — a database
// pool lands here when the first repository does — and growing a struct does
// not rewrite every call site.
type Deps struct {
	// Config is the whole document. The module picks out its own sections and
	// passes values, never the Config, to what it builds.
	Config *config.Config
	// Logger is the process logger; the module scopes it to itself.
	Logger *slog.Logger
	// Clock is the time source, injected so credential expiry stays
	// deterministic under test.
	Clock wallet.Clock
}

// Module is the assembled context.
type Module struct {
	wallet  *wallet.Service
	adapter *fafnir.Adapter
	router  *rest.CoreRouter
	logger  *slog.Logger
	budget  time.Duration

	// background owns the goroutine that keeps retrying the wallet handshake,
	// so Close can wait for it instead of leaving it writing to a logger the
	// process believes it has finished with.
	background sync.WaitGroup
	cancel     context.CancelFunc
}

// New assembles the context.
func New(deps Deps) (*Module, error) {
	if deps.Config == nil {
		return nil, fmt.Errorf("%s: no configuration given", Name)
	}

	walletURL, err := deps.Config.Wallet.APIURL(config.HostHTTP)
	if err != nil {
		return nil, fmt.Errorf("%s: resolving the wallet endpoint: %w", Name, err)
	}

	logger := observability.Scoped(deps.Logger, observability.ModuleSSIAuth, "")

	adapter, err := fafnir.New(walletURL, observability.Scoped(deps.Logger, observability.ModuleSSIAuth, "fafnir"))
	if err != nil {
		return nil, fmt.Errorf("%s: building the wallet adapter: %w", Name, err)
	}

	service := wallet.NewService(adapter, deps.Clock,
		observability.Scoped(deps.Logger, observability.ModuleSSIAuth, "wallet"))

	return &Module{
		wallet:  service,
		adapter: adapter,
		router:  rest.NewCoreRouter(rest.NewWalletRouter(service)),
		logger:  logger,
		budget:  deps.Config.Wallet.StartupLinkTimeout,
	}, nil
}

// Name identifies the context.
func (m *Module) Name() string { return Name }

// Wallet exposes the use cases, for a caller that needs them directly.
func (m *Module) Wallet() *wallet.Service { return m.wallet }

// Register mounts the context's HTTP surface under the versioned API group.
func (m *Module) Register(api *gin.RouterGroup) { m.router.Register(api) }

// RegisterRoot mounts the routes a specification pins to the root of the
// origin, outside any version prefix.
func (m *Module) RegisterRoot(engine *gin.Engine) { m.router.RegisterRoot(engine) }

// Checks are the context's contributions to readiness. The names are what an
// operator reads off the probe, so they say what is missing, not which package
// is unhappy.
func (m *Module) Checks() map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"wallet": func(ctx context.Context) error {
			if !m.wallet.IsLinked(ctx) {
				return fmt.Errorf("no identity established: %w", observability.ErrNotReady)
			}

			return nil
		},
	}
}

// Describe reports the identity for the startup report, once there is one.
func (m *Module) Describe() (string, bool) {
	identity, err := m.wallet.Did(context.Background())
	if err != nil {
		return "", false
	}

	return identity, true
}

// Start acquires the identity everything else in this context depends on.
//
// It spends a bounded budget on the handshake and then hands the job to a
// background goroutine. Blocking briefly catches the common case, where the
// node and its wallet start together and the wallet is seconds behind; past the
// budget, refusing to start would only produce a restart loop. The context
// comes up, reports itself not ready, and keeps trying — which is what an
// orchestrator knows how to act on.
func (m *Module) Start(ctx context.Context) error {
	// A context of its own, so Close can stop the retry loop however the
	// process exits.
	ctx, m.cancel = context.WithCancel(ctx)

	budgeted, cancel := context.WithTimeout(ctx, m.budget)
	defer cancel()

	if _, err := m.link(budgeted, true); err == nil {
		return nil
	}

	m.logger.WarnContext(ctx, "wallet not linked within the startup budget; retrying in the background",
		"budget", m.budget.String())

	m.background.Add(1)

	go func() {
		defer m.background.Done()

		if _, err := m.link(ctx, false); err != nil {
			// The only way out of the loop besides success is the process
			// shutting down, so this is expected on the way out.
			m.logger.InfoContext(ctx, "wallet link abandoned", "err", err)
		}
	}()

	return nil
}

// link retries the handshake until it succeeds or the context ends, pausing on
// a capped exponential backoff. It reports each failed attempt only while
// announce is set, so the background loop does not narrate an outage forever.
func (m *Module) link(ctx context.Context, announce bool) (wallet.Did, error) {
	backoff := linkFirstBackoff

	for attempt := 1; ; attempt++ {
		identity, err := m.wallet.Link(ctx)
		if err == nil {
			return identity, nil
		}

		// The budget and the shutdown signal both land here as a cancelled
		// context, and neither is worth another attempt.
		if ctx.Err() != nil {
			return wallet.Did{}, fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		}

		if announce {
			m.logger.WarnContext(ctx, "wallet not ready",
				"attempt", attempt, "retry_in", backoff.String(), "err", err)
		}

		select {
		case <-ctx.Done():
			return wallet.Did{}, fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		case <-time.After(backoff):
		}

		// No jitter: there is one client here, so there is no herd to spread.
		backoff = min(backoff*2, linkMaxBackoff)
	}
}

// Close stops the background handshake, waits for it, and releases the adapter.
func (m *Module) Close() error {
	if m.cancel != nil {
		m.cancel()
	}

	m.background.Wait()

	if err := m.adapter.Close(); err != nil {
		return fmt.Errorf("%s: closing the wallet adapter: %w", Name, err)
	}

	return nil
}

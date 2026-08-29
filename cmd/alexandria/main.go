// Package main is the entry point of the alexandria binary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/httpapi"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/fafnir"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

// Server timeouts. Only ReadHeaderTimeout protects against the slow-header
// attack; the rest keep a stalled peer from holding a connection indefinitely.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 10 * time.Second
)

// Wallet handshake backoff. The first pause is short because the common case is
// a wallet seconds away from ready; the cap keeps a long outage from stretching
// the gap out to something useless.
const (
	linkFirstBackoff = 500 * time.Millisecond
	linkMaxBackoff   = 10 * time.Second
)

// systemClock is the production implementation of the wallet Clock port. It
// lives at the composition root because it is the only place allowed to reach
// for real wall-clock time.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func main() {
	// main only translates the error into an exit code: os.Exit skips
	// deferred calls, so any logic needing cleanup lives in run.
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run takes its dependencies as parameters so tests can exercise it directly.
func run(ctx context.Context, args []string, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(args, stdout)
	if err != nil {
		return err
	}

	root, err := observability.NewLogger(stdout, cfg.Observability,
		slog.String("service", "alexandria"),
		slog.String("version", version),
	)
	if err != nil {
		return err
	}

	// The composition root logs under its own name; every subsystem gets a
	// logger scoped to its module and component.
	logger := observability.Scoped(root, observability.ModuleMain, "")

	// A human at a terminal gets the table; a log pipeline gets the same facts
	// as one record it can actually index.
	out := newReport(stdout, os.Environ())

	if observability.UsesJSON(stdout, cfg.Observability.LogFormat) {
		logger.InfoContext(ctx, "configuration loaded", summaryAttrs(cfg)...)
	} else if err := out.summary(version, cfg); err != nil {
		return err
	}

	metrics, err := startMetrics(cfg)
	if err != nil {
		return err
	}

	defer shutdownMetrics(ctx, metrics, logger)

	walletService, closeWallet, err := buildWallet(cfg, logger)
	if err != nil {
		return err
	}

	defer closeWallet()

	health := observability.NewHealth()
	health.Register("wallet", walletCheck(walletService))

	// The background linker gets a context of its own so run can shut it down
	// and wait for it, whichever way it returns. A goroutine that outlives the
	// function that started it is a leak, and it would go on writing to a
	// writer the caller believes it owns again.
	linkCtx, cancelLink := context.WithCancel(ctx)
	defer cancelLink()

	var background sync.WaitGroup

	defer background.Wait()

	linkWallet(linkCtx, &background, walletService, cfg.Wallet.StartupLinkTimeout, out, logger)

	engine, err := buildEngine(cfg, health, walletService, metrics, root)
	if err != nil {
		return err
	}

	internal := observability.NewInternalServer(cfg.Observability, metrics,
		observability.Scoped(root, observability.ModuleObservability, "internal"))
	internal.Start()

	if addr := internal.Addr(); addr != "" {
		if err := out.internal(addr, cfg.Observability); err != nil {
			return err
		}
	}

	return serve(ctx, cfg, engine, internal, out, logger)
}

// ===== Wiring ================================================================

// startMetrics builds the metric pipeline, or returns nil when metrics are off.
func startMetrics(cfg *config.Config) (*observability.Metrics, error) {
	if !cfg.Observability.Metrics {
		return nil, nil //nolint:nilnil // no pipeline is a valid outcome, not a failure
	}

	metrics, err := observability.NewMetrics(version)
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

// shutdownMetrics flushes the pipeline on the way out, so the measurements
// taken since the last scrape are not simply dropped.
func shutdownMetrics(ctx context.Context, metrics *observability.Metrics, logger *slog.Logger) {
	if metrics == nil {
		return
	}

	// WithoutCancel, not Background: this runs while the parent is already
	// cancelled by the shutdown signal, but the trace and baggage on it still
	// belong to this process.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	if err := metrics.Shutdown(ctx); err != nil {
		logger.Error("flushing metrics", "err", err)
	}
}

// buildWallet wires the wallet adapter and its use cases, returning the closer
// the caller must defer.
func buildWallet(cfg *config.Config, logger *slog.Logger) (*wallet.Service, func(), error) {
	walletURL, err := cfg.Wallet.APIURL(config.HostHTTP)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving the wallet endpoint: %w", err)
	}

	adapter, err := fafnir.New(walletURL, observability.Scoped(logger, observability.ModuleSSIAuth, "fafnir"))
	if err != nil {
		return nil, nil, fmt.Errorf("building the wallet adapter: %w", err)
	}

	service := wallet.NewService(adapter, systemClock{},
		observability.Scoped(logger, observability.ModuleSSIAuth, "wallet"))

	return service, func() { _ = adapter.Close() }, nil
}

// walletCheck is the readiness check for the wallet: the node can serve once it
// knows who it is, and not before.
func walletCheck(holder *wallet.Service) observability.Check {
	return func(ctx context.Context) error {
		if !holder.IsLinked(ctx) {
			return fmt.Errorf("no identity established: %w", observability.ErrNotReady)
		}

		return nil
	}
}

// buildEngine assembles the HTTP stack.
//
// gin.New rather than gin.Default: the default engine installs gin's own logger
// and recovery, which write unstructured lines that carry no request id and
// answer panics in a body shape the rest of the API does not use.
func buildEngine(
	cfg *config.Config,
	health *observability.Health,
	holder *wallet.Service,
	metrics *observability.Metrics,
	logger *slog.Logger,
) (*gin.Engine, error) {
	if cfg.Common.Connection.IsProd {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()

	// Order matters: the request id has to exist before anything logs, and
	// recovery has to wrap the handlers it is protecting.
	// Scoped here rather than inside rest: the package should not have to know
	// which module of the tree it was mounted under.
	restLogger := observability.Scoped(logger, observability.ModuleSSIAuth, "rest")

	engine.Use(rest.RequestID(), rest.Recovery(restLogger), rest.AccessLog(restLogger))

	if metrics != nil {
		middleware, err := rest.Metrics(metrics.Meter("alexandria/http"))
		if err != nil {
			return nil, fmt.Errorf("building the metrics middleware: %w", err)
		}

		engine.Use(middleware)
	}

	httpapi.NewRouter(health, rest.NewCoreRouter(rest.NewWalletRouter(holder))).Register(engine)

	return engine, nil
}

// ===== Wallet handshake ======================================================

// linkWallet spends a bounded budget trying to link, then hands the job to a
// background goroutine.
//
// Blocking briefly catches the common case, where the node and its wallet start
// together and the wallet is seconds behind. Past the budget, refusing to start
// would only produce a restart loop: the node comes up, reports itself not
// ready, and keeps trying — which is what an orchestrator knows how to act on.
func linkWallet(
	ctx context.Context,
	background *sync.WaitGroup,
	holder *wallet.Service,
	budget time.Duration,
	out *report,
	logger *slog.Logger,
) {
	notify := func(attempt int, backoff time.Duration, err error) {
		if reportErr := out.waiting(attempt, backoff.String(), err.Error()); reportErr != nil {
			logger.WarnContext(ctx, "wallet not ready", "attempt", attempt, "err", err)
		}
	}

	budgeted, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	identity, err := retryLink(budgeted, holder, notify)
	if err == nil {
		logger.InfoContext(ctx, "wallet linked", "did", identity.ID, "alias", identity.Alias)

		if reportErr := out.linked(identity); reportErr != nil {
			logger.WarnContext(ctx, "writing the startup report", "err", reportErr)
		}

		return
	}

	logger.WarnContext(ctx, "wallet not linked within the startup budget; retrying in the background",
		"budget", budget.String(), "err", err)

	background.Add(1)

	go func() {
		defer background.Done()

		identity, err := retryLink(ctx, holder, nil)
		if err != nil {
			// The only way out of the loop besides success is the process
			// shutting down, so this is expected on the way out.
			logger.InfoContext(ctx, "wallet link abandoned", "err", err)

			return
		}

		logger.InfoContext(ctx, "wallet linked", "did", identity.ID, "alias", identity.Alias)
	}()
}

// retryLink attempts the handshake until it succeeds or the context ends,
// pausing on a capped exponential backoff between attempts.
func retryLink(
	ctx context.Context,
	holder *wallet.Service,
	notify func(attempt int, backoff time.Duration, err error),
) (wallet.Did, error) {
	backoff := linkFirstBackoff

	for attempt := 1; ; attempt++ {
		identity, err := holder.Link(ctx)
		if err == nil {
			return identity, nil
		}

		// The budget and the shutdown signal both land here as a cancelled
		// context, and neither is worth another attempt.
		if ctx.Err() != nil {
			return wallet.Did{}, fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		}

		if notify != nil {
			notify(attempt, backoff, err)
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

// ===== Serving ===============================================================

// serve runs the API until the context ends, then drains both listeners.
func serve(
	ctx context.Context,
	cfg *config.Config,
	engine *gin.Engine,
	internal *observability.InternalServer,
	out *report,
	logger *slog.Logger,
) error {
	// The port the process listens on is the internal one: outside the cluster
	// the deployment may publish it somewhere else entirely.
	server := &http.Server{
		Addr:              ":" + cfg.Common.Hosts.HTTP.PrivatePort(),
		Handler:           engine,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	if err := out.listening(server.Addr); err != nil {
		return err
	}

	logger.InfoContext(ctx, "listening", "addr", server.Addr)

	// The server runs in its own goroutine so the main flow can block on ctx
	// and drive the graceful shutdown when a signal arrives.
	serverErr := make(chan error, 1)

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("serving http: %w", err)

			return
		}

		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down http server: %w", err)
		}

		if err := internal.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutting down the internal listener", "err", err)
		}

		return <-serverErr
	}
}

// ===== Configuration =========================================================

// configEnvVar names the deployment file when no --config flag is given.
const configEnvVar = "ALEXANDRIA_CONFIG"

// searchPaths are the directories Discover falls back to when neither the flag
// nor the environment names a file.
var searchPaths = []string{".", "./config", "/etc/alexandria"}

// loadConfig resolves the deployment file: the --config flag wins, then
// $ALEXANDRIA_CONFIG, then a search for config.yaml in the usual places.
//
// Flag parsing writes to the caller's writer and reports the error rather than
// exiting, so run stays testable and its deferred cleanup still runs.
func loadConfig(args []string, out io.Writer) (*config.Config, error) {
	flags := flag.NewFlagSet("alexandria", flag.ContinueOnError)
	flags.SetOutput(out)

	path := flags.String("config", os.Getenv(configEnvVar),
		"path to the deployment YAML (defaults to $"+configEnvVar+")")

	if err := flags.Parse(args); err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}

	if *path != "" {
		cfg, err := config.Load(*path)
		if err != nil {
			return nil, fmt.Errorf("loading config: %w", err)
		}

		return cfg, nil
	}

	cfg, err := config.Discover(searchPaths...)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	return cfg, nil
}

// Wiring: the constructors that turn configuration into running components.
//
// Every one of them takes the whole *config.Config and picks out what it needs.
// Configuration goes in, a configured component comes out. That uniformity is
// worth more here than minimal parameters: adding a setting to a component
// stops being a change to its call site, and a reader can tell at a glance
// which functions are wiring and which are not.
//
// The rule stops at this package. Config is the composition root's input, and
// it does not travel past it: the constructors under internal/ take the values
// they were given, so no service can reach for a setting it did not declare a
// dependency on, and none of them has to import the deployment format.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/httpapi"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/fafnir"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/caparicio-esd/alexandria/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

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

// openDatabase builds the connection pool, or returns nil when this deployment
// runs without a database.
func openDatabase(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*postgres.Pool, error) {
	if !cfg.Common.DB.IsPostgres() {
		logger.InfoContext(ctx, "running without a database", "driver", cfg.Common.DB.Driver)

		return nil, nil //nolint:nilnil // no database is a valid deployment, not a failure
	}

	pool, err := postgres.Open(ctx, cfg.Common.DB,
		observability.Scoped(logger, observability.ModuleStorage, "postgres"))
	if err != nil {
		return nil, fmt.Errorf("opening the database: %w", err)
	}

	return pool, nil
}

// buildInternalServer wires the diagnostics listener, or returns nil when the
// configuration switches it off.
func buildInternalServer(
	cfg *config.Config,
	metrics *observability.Metrics,
	logger *slog.Logger,
) *observability.InternalServer {
	return observability.NewInternalServer(cfg.Observability, metrics,
		observability.Scoped(logger, observability.ModuleObservability, "internal"))
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

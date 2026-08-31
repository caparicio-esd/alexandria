// Wiring: the infrastructure constructors newApp draws on.
//
// Every one of them takes the whole *config.Config and picks out what it needs.
// Configuration goes in, a configured component comes out. That uniformity is
// worth more here than minimal parameters: adding a setting to a component
// stops being a change to its call site, and a reader can tell at a glance
// which functions are wiring and which are not.
//
// The rule stops at this package. Config is the composition root's input, and
// it does not travel past it — except into a module, which is a composition
// root of its own and picks out its sections the same way.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
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

// buildEngine assembles the HTTP stack, middleware only: the routes are mounted
// by the root router, from the modules.
//
// gin.New rather than gin.Default: the default engine installs gin's own logger
// and recovery, which write unstructured lines that carry no request id and
// answer panics in a body shape the rest of the API does not use.
func buildEngine(cfg *config.Config, metrics *observability.Metrics, logger *slog.Logger) (*gin.Engine, error) {
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

	return engine, nil
}

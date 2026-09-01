// The global composition: configuration goes in, a wired application comes out.
//
// newApp is the single place where concrete implementations meet. Nothing above
// it constructs anything, and nothing below it reaches upwards: main resolves
// which document to load, hands it here, and hands the result to Run. That
// split is what makes the wiring reviewable in one sitting and testable without
// a process.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	authproxy "github.com/caparicio-esd/alexandria/internal/auth-proxy"
	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/httpapi"
	"github.com/caparicio-esd/alexandria/internal/observability"
	ssiauth "github.com/caparicio-esd/alexandria/internal/ssi-auth"
	"github.com/caparicio-esd/alexandria/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

// Module is a bounded context the process mounts and supervises.
//
// The interface is declared here, where it is consumed, rather than exported by
// the contexts — so a context satisfies it by having the right methods, without
// importing the composition root. Adding the vocabulary hub means writing one
// more module and adding it to newApp's list; nothing else in this file moves.
type Module interface {
	// Name identifies the context in logs and reports.
	Name() string
	// Start acquires whatever the context needs before it can serve. A context
	// that comes up degraded returns nil and says so through its checks.
	Start(ctx context.Context) error
	// Register mounts the context's HTTP surface under the versioned API
	// group the router hands it. A context that also needs a route at the root
	// of the origin implements httpapi.RootModule as well.
	Register(api *gin.RouterGroup)
	// Checks are the context's contributions to readiness, by name.
	Checks() map[string]func(context.Context) error
	// Close releases what the context owns, including its goroutines.
	Close() error
}

// describer is optional: a module with something worth showing in the startup
// report implements it. Optional interfaces keep the contract above minimal —
// a context with nothing to say does not have to say nothing.
type describer interface {
	Describe() (string, bool)
}

// App is the wired application: everything constructed, nothing started.
type App struct {
	config   *config.Config
	logger   *slog.Logger
	report   *report
	metrics  *observability.Metrics
	health   *observability.Health
	database *postgres.Pool
	internal *observability.InternalServer
	engine   *gin.Engine
	modules  []Module
}

// newApp performs the whole injection: configuration in, wired application out.
//
// The order is the dependency order, and it is the only place that order
// exists: infrastructure first, then the contexts that use it, then the HTTP
// surface that exposes them.
func newApp(ctx context.Context, cfg *config.Config, stdout io.Writer, environ []string) (*App, error) {
	logger, err := observability.NewLogger(stdout, cfg.Observability,
		slog.String("service", "alexandria"),
		slog.String("version", version),
	)
	if err != nil {
		return nil, err
	}

	app := &App{
		config: cfg,
		logger: observability.Scoped(logger, observability.ModuleMain, ""),
		report: newReport(stdout, environ),
		health: observability.NewHealth(),
	}

	// Announced before anything it describes gets a chance to log, so the
	// table is the first thing on the terminal rather than the third.
	if observability.UsesJSON(stdout, cfg.Observability.LogFormat) {
		app.logger.InfoContext(ctx, "configuration loaded", summaryAttrs(cfg)...)
	} else if err := app.report.summary(version, cfg); err != nil {
		return nil, err
	}

	if app.metrics, err = startMetrics(cfg); err != nil {
		return nil, err
	}

	if app.database, err = openDatabase(ctx, cfg, logger); err != nil {
		return nil, err
	}

	if app.database != nil {
		app.health.Register("database", app.database.Check)
	}

	// ===== Bounded contexts ==================================================
	// One entry per hexagon. Each is handed what it needs and returns itself
	// assembled; the composition root never sees their adapters.
	ssiAuthModule, err := ssiauth.New(ssiauth.Deps{
		Config: cfg,
		Logger: logger,
		Clock:  systemClock{},
	})
	if err != nil {
		return nil, err
	}

	// The authentication boundary. It is a module like any other — it starts,
	// reports readiness and closes — and additionally the guard the router puts
	// in front of every route under the API prefix. Disabled, it is absent
	// entirely and nothing is protected, which is a development posture.
	var guard httpapi.Guard

	app.modules = []Module{ssiAuthModule}

	if cfg.Auth.Enabled {
		authModule, err := authproxy.New(authproxy.Deps{
			Config: cfg,
			Logger: logger,
			Now:    time.Now,
		})
		if err != nil {
			return nil, err
		}

		guard = authModule
		app.modules = append(app.modules, authModule)
	} else {
		app.logger.WarnContext(ctx, "authentication is disabled: every route under "+
			httpapi.APIPrefix+" is open")
	}

	for _, module := range app.modules {
		for name, check := range module.Checks() {
			app.health.Register(name, check)
		}
	}

	if app.engine, err = buildEngine(cfg, app.metrics, logger); err != nil {
		return nil, err
	}

	httpapi.NewRouter(app.health, guard, modulesAsRoutes(app.modules)...).Register(app.engine)

	app.internal = buildInternalServer(cfg, app.metrics, logger)

	return app, nil
}

// modulesAsRoutes narrows the modules to what the router needs. Go will not
// convert a []Module to a []httpapi.Module on its own, and the loop is cheaper
// than making either interface know about the other.
func modulesAsRoutes(modules []Module) []httpapi.Module {
	routes := make([]httpapi.Module, 0, len(modules))
	for _, module := range modules {
		routes = append(routes, module)
	}

	return routes
}

// Start brings up the diagnostics listener and every context.
func (a *App) Start(ctx context.Context) error {
	a.internal.Start()

	if addr := a.internal.Addr(); addr != "" {
		if err := a.report.internal(addr, a.config.Observability); err != nil {
			return err
		}
	}

	for _, module := range a.modules {
		if err := module.Start(ctx); err != nil {
			return fmt.Errorf("starting %s: %w", module.Name(), err)
		}

		detail := ""
		if described, ok := module.(describer); ok {
			if text, found := described.Describe(); found {
				detail = text
			}
		}

		if err := a.report.module(module.Name(), detail); err != nil {
			return err
		}
	}

	return nil
}

// Close releases everything the app owns, in reverse dependency order, and
// reports every failure rather than the first: a leaked connection is not worth
// hiding behind a failed flush.
func (a *App) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	errs := make([]error, 0, len(a.modules)+2)

	for _, module := range a.modules {
		if err := module.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := a.internal.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}

	if a.database != nil {
		a.database.Close()
	}

	if a.metrics != nil {
		if err := a.metrics.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

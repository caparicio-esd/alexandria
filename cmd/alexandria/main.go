// Package main is the entry point of the alexandria binary.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/caparicio-esd/alexandria/internal/observability"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

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

	database, err := openDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}

	if database != nil {
		defer database.Close()
	}

	walletService, closeWallet, err := buildWallet(cfg, logger)
	if err != nil {
		return err
	}

	defer closeWallet()

	health := observability.NewHealth()
	health.Register("wallet", walletCheck(walletService))

	if database != nil {
		health.Register("database", database.Check)
	}

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

// Package main is the entry point of the alexandria binary.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
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

// run is the whole life of the process, in the three steps it actually has:
// resolve the configuration, inject the dependencies, serve until told to stop.
//
// It takes its dependencies as parameters so tests can exercise it directly.
func run(ctx context.Context, args []string, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(args, stdout)
	if err != nil {
		return err
	}

	app, err := newApp(ctx, cfg, stdout, os.Environ())
	if err != nil {
		return err
	}

	// Close is deferred before Start so a context that fails halfway still
	// releases what the ones before it acquired.
	defer func() {
		if err := app.Close(ctx); err != nil {
			app.logger.Error("shutting down", "err", err)
		}
	}()

	if err := app.Start(ctx); err != nil {
		return err
	}

	return app.Serve(ctx)
}

// Package main is the entry point of the alexandria binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/fafnir"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
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
func run(ctx context.Context, _ []string, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if _, err := fmt.Fprintf(stdout, "alexandria %s\n", version); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	// Composition root: concrete implementations are wired here, once, from
	// the inside of the hexagon outwards.
	walletFafnirAdapter, _ := fafnir.New("http://localhost:7002")
	walletService := wallet.NewService(walletFafnirAdapter, systemClock{})
	walletRouter := rest.NewWalletRouter(walletService)
	coreRouter := rest.NewCoreRouter(walletRouter)

	engine := gin.Default()
	coreRouter.Register(engine)

	server := &http.Server{
		Addr:              ":1234",
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
	}

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
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down http server: %w", err)
		}
		return <-serverErr
	}
}

// Package main is the entry point of the alexandria binary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
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

// The wallet handshake is retried on a capped exponential backoff: a node and
// its wallet usually start together, so the first few attempts failing is
// normal rather than fatal.
const (
	// linkTimeout bounds the whole handshake. Past it, a node that cannot
	// reach its wallet should fail its health check rather than hang forever
	// pretending to start.
	linkTimeout = 2 * time.Minute
	// linkFirstBackoff is short, because the common case is a wallet that is
	// seconds away from being ready.
	linkFirstBackoff = 500 * time.Millisecond
	// linkMaxBackoff keeps a long outage from stretching the gap out to
	// something useless.
	linkMaxBackoff = 10 * time.Second
)

// linkWallet blocks until the wallet reports an identity, the deadline passes
// or the process is asked to stop.
//
// It is deliberately part of startup: every route below /wallet needs an
// identity, and a node that answers requests before it has one would serve
// errors that look like bugs. The cost is that the node does not come up
// without its wallet, which is the honest description of what it is.
//
// The retry policy lives here, at the composition root, and not in the service:
// how long to wait for a dependency is a deployment decision, not a business
// rule.
func linkWallet(ctx context.Context, holder *wallet.Service, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, linkTimeout)
	defer cancel()

	backoff := linkFirstBackoff

	for attempt := 1; ; attempt++ {
		identity, err := holder.Link(ctx)
		if err == nil {
			if _, err := fmt.Fprintf(out, "linked as %s\n", identity.ID); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}

			return nil
		}

		// The deadline and the signal both land here as a cancelled context,
		// and neither is worth another attempt.
		if ctx.Err() != nil {
			return fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		}

		if _, err := fmt.Fprintf(out, "wallet not ready (attempt %d, retrying in %s): %v\n",
			attempt, backoff, err); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		case <-time.After(backoff):
		}

		// No jitter: there is one client here, so there is no herd to spread.
		backoff = min(backoff*2, linkMaxBackoff)
	}
}

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

// run takes its dependencies as parameters so tests can exercise it directly.
func run(ctx context.Context, args []string, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(args, stdout)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stdout, "alexandria %s\n", version); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	walletURL, err := cfg.Wallet.APIURL(config.HostHTTP)
	if err != nil {
		return fmt.Errorf("resolving the wallet endpoint: %w", err)
	}

	// Composition root: concrete implementations are wired here, once, from
	// the inside of the hexagon outwards. Each constructor gets the values it
	// needs, never the whole configuration.
	walletAdapter, err := fafnir.New(walletURL)
	if err != nil {
		return fmt.Errorf("building the wallet adapter: %w", err)
	}

	defer func() { _ = walletAdapter.Close() }()

	walletService := wallet.NewService(walletAdapter, systemClock{})
	walletRouter := rest.NewWalletRouter(walletService)
	coreRouter := rest.NewCoreRouter(walletRouter)

	if err := linkWallet(ctx, walletService, stdout); err != nil {
		return err
	}

	engine := gin.Default()
	coreRouter.Register(engine)

	// The port the process listens on is the internal one: outside the
	// cluster the deployment may publish it somewhere else entirely.
	server := &http.Server{
		Addr:              ":" + cfg.Common.Hosts.HTTP.PrivatePort(),
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

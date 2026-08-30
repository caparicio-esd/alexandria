// Serving: the API listener and its graceful shutdown.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/gin-gonic/gin"
)

// Server timeouts. Only ReadHeaderTimeout protects against the slow-header
// attack; the rest keep a stalled peer from holding a connection indefinitely.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 10 * time.Second
)

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

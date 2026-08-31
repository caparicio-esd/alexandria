// Serving: the API listener and its graceful shutdown.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
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

// Serve runs the API until the context ends, then drains the listener.
//
// Everything else the app owns is released by Close, which run defers: a
// shutdown path split across two functions is how a connection survives the
// process that opened it.
func (a *App) Serve(ctx context.Context) error {
	// The port the process listens on is the internal one: outside the cluster
	// the deployment may publish it somewhere else entirely.
	server := &http.Server{
		Addr:              ":" + a.config.Common.Hosts.HTTP.PrivatePort(),
		Handler:           a.engine,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	if err := a.report.listening(server.Addr); err != nil {
		return err
	}

	a.logger.InfoContext(ctx, "listening", "addr", server.Addr)

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
		a.logger.Info("shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down http server: %w", err)
		}

		return <-serverErr
	}
}

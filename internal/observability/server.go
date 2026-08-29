package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
)

// internalTimeouts keep the diagnostics listener from being a way to hold
// connections open. They are generous: a heap profile legitimately takes a
// while to write.
const (
	internalReadHeaderTimeout = 5 * time.Second
	internalWriteTimeout      = 60 * time.Second
	internalIdleTimeout       = 60 * time.Second
)

// InternalServer carries the endpoints that describe the process rather than
// the dataspace: the Prometheus scrape endpoint and, when enabled, pprof.
//
// It listens on its own port so that publishing the API does not publish the
// diagnostics. A heap profile names everything the process has in memory.
type InternalServer struct {
	server *http.Server
	logger *slog.Logger
}

// NewInternalServer wires the enabled endpoints. It returns nil when the
// configuration switches the listener off, which callers must handle — a nil
// server is a valid deployment, not an error.
func NewInternalServer(cfg config.Observability, metrics *Metrics, logger *slog.Logger) *InternalServer {
	addr := cfg.InternalAddr()
	if addr == "" {
		return nil
	}

	mux := http.NewServeMux()

	if cfg.Metrics && metrics != nil {
		mux.Handle("GET /metrics", metrics.Handler())
	}

	if cfg.Pprof {
		// Registered by hand rather than through the side effect of importing
		// net/http/pprof, which would bolt these onto http.DefaultServeMux and
		// so onto anything that ever serves it.
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}

	return &InternalServer{
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: internalReadHeaderTimeout,
			WriteTimeout:      internalWriteTimeout,
			IdleTimeout:       internalIdleTimeout,
		},
		logger: logger,
	}
}

// Addr is the address the listener was configured with.
func (s *InternalServer) Addr() string {
	if s == nil {
		return ""
	}

	return s.server.Addr
}

// Start serves in the background and reports a failure on the returned channel.
//
// The internal listener never takes the process down: losing metrics is worth
// a loud log line, not an outage on the API.
func (s *InternalServer) Start() {
	if s == nil {
		return
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("internal listener stopped", "addr", s.server.Addr, "err", err)
		}
	}()
}

// Shutdown stops the listener.
func (s *InternalServer) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutting down the internal listener: %w", err)
	}

	return nil
}

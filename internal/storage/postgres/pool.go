// Package postgres owns the connection pool.
//
// It sits beside the hexagon, like the rest of the infrastructure: the pool is
// a process resource, opened once at the composition root and handed to
// whichever bounded context needs it. The repositories that speak SQL belong to
// their own context, not here.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pingTimeout bounds the boot-time reachability check. It is short on purpose:
// the point is to tell the operator now, not to hold the process hostage.
const pingTimeout = 5 * time.Second

// ErrUnreachable reports that the server did not answer.
var ErrUnreachable = errors.New("database unreachable")

// Pool is the process-wide connection pool.
//
// The embedded *pgxpool.Pool is the query surface; the wrapper exists for the
// readiness check and for keeping the logger alongside it.
type Pool struct {
	*pgxpool.Pool

	logger *slog.Logger
}

// Open builds the pool from the configuration and the run-time credentials.
//
// The pool is lazy and self-healing: pgxpool dials on first use and reconnects
// on its own, so a database that is down at boot is not a reason to refuse to
// start. Open therefore reports an unreachable server rather than failing —
// readiness is where that belongs, and a pool that reconnects will clear it
// without a restart.
func Open(ctx context.Context, cfg config.Database, logger *slog.Logger) (*Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		// The DSN is assembled from validated configuration, so this is a bug
		// in the assembly rather than operator error.
		return nil, fmt.Errorf("parsing the database dsn: %w", err)
	}

	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("building the database pool: %w", err)
	}

	wrapped := &Pool{Pool: pool, logger: logger}

	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	if err := wrapped.Check(pingCtx); err != nil {
		// Redacted, never DSN: a connection string in a log line is a password
		// in a log aggregator.
		logger.WarnContext(ctx, "database unreachable at boot; the pool will keep retrying",
			"dsn", cfg.Redacted(), "err", err)

		return wrapped, nil
	}

	logger.InfoContext(ctx, "database connected",
		"dsn", cfg.Redacted(), "max_conns", cfg.MaxConns)

	return wrapped, nil
}

// Check is the readiness check: it reports whether the server answers right
// now. Its signature matches observability.Check, so it registers directly.
func (p *Pool) Check(ctx context.Context) error {
	if err := p.Ping(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}

	return nil
}

// Close releases every connection. It is called once, on the way out.
func (p *Pool) Close() {
	p.logger.Debug("closing the database pool")
	p.Pool.Close()
}

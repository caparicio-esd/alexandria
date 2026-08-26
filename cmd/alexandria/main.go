// Package main is the entry point of the alexandria binary.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

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

	return ctx.Err()
}

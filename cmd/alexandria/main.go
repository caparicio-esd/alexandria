// Package main es el punto de entrada del binario alexandria.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version se inyecta en tiempo de compilacion con -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// main solo traduce el error a un codigo de salida: os.Exit se salta
	// los defer, asi que toda la logica con limpieza vive en run.
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run recibe sus dependencias por parametro para poder ejercitarse desde los tests.
func run(ctx context.Context, _ []string, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if _, err := fmt.Fprintf(stdout, "alexandria %s\n", version); err != nil {
		return fmt.Errorf("escribiendo salida: %w", err)
	}

	return ctx.Err()
}

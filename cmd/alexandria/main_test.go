package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args []string
		want string
	}{
		"sin argumentos": {args: nil, want: "alexandria dev"},
		"con argumentos": {args: []string{"-x"}, want: "alexandria dev"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			if err := run(context.Background(), tc.args, &out); err != nil {
				t.Fatalf("run() error inesperado: %v", err)
			}

			if got := strings.TrimSpace(out.String()); got != tc.want {
				t.Errorf("run() escribio %q, se esperaba %q", got, tc.want)
			}
		})
	}
}

func TestRunContextCancelado(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out bytes.Buffer
	if err := run(ctx, nil, &out); err == nil {
		t.Fatal("run() con contexto cancelado deberia devolver error")
	}
}

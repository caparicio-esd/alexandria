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
		"no arguments":   {args: nil, want: "alexandria dev"},
		"with arguments": {args: []string{"-x"}, want: "alexandria dev"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			if err := run(context.Background(), tc.args, &out); err != nil {
				t.Fatalf("run() unexpected error: %v", err)
			}

			if got := strings.TrimSpace(out.String()); got != tc.want {
				t.Errorf("run() wrote %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out bytes.Buffer
	if err := run(ctx, nil, &out); err == nil {
		t.Fatal("run() with a cancelled context should return an error")
	}
}

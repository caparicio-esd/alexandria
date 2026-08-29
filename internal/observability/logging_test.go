package observability_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/observability"
)

func TestLoggerCarriesTheRequestID(t *testing.T) {
	var out bytes.Buffer

	logger, err := observability.NewLogger(&out,
		config.Observability{LogLevel: "info", LogFormat: config.LogFormatJSON},
		slog.String("service", "alexandria"),
	)
	if err != nil {
		t.Fatalf("NewLogger() = %v", err)
	}

	ctx := observability.WithRequestID(context.Background(), "abc-123")
	logger.InfoContext(ctx, "request")

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("decoding the record: %v\n%s", err, out.String())
	}

	// Correlation cannot depend on every call site remembering the id.
	if got := record["request_id"]; got != "abc-123" {
		t.Errorf("request_id = %v, want abc-123", got)
	}

	if got := record["service"]; got != "alexandria" {
		t.Errorf("service = %v, want alexandria", got)
	}
}

func TestLoggerHonoursTheLevel(t *testing.T) {
	var out bytes.Buffer

	logger, err := observability.NewLogger(&out,
		config.Observability{LogLevel: "warn", LogFormat: config.LogFormatJSON})
	if err != nil {
		t.Fatalf("NewLogger() = %v", err)
	}

	logger.Info("dropped")

	if out.Len() != 0 {
		t.Errorf("info record emitted at warn level: %s", out.String())
	}

	logger.Warn("kept")

	if out.Len() == 0 {
		t.Error("warn record dropped at warn level")
	}
}

// TestAutoFormatIsJSONOffTerminal pins the auto rule: anything that is not a
// terminal — a pipe, a file, a container's stdout — gets JSON.
func TestAutoFormatIsJSONOffTerminal(t *testing.T) {
	var out bytes.Buffer

	if !observability.UsesJSON(&out, config.LogFormatAuto) {
		t.Error("UsesJSON() = false for a non-terminal writer, want true")
	}

	if observability.UsesJSON(&out, config.LogFormatText) {
		t.Error("UsesJSON() = true for an explicit text format")
	}
}

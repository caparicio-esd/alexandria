package observability_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/observability"
)

func TestLivenessIgnoresDependencies(t *testing.T) {
	t.Parallel()

	health := observability.NewHealth()
	health.Register("wallet", func(context.Context) error {
		return errors.New("wallet is on fire")
	})

	recorder := httptest.NewRecorder()
	health.LiveHandler().ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))

	// A failing dependency must never restart the process: liveness answers for
	// the process alone.
	if recorder.Code != http.StatusOK {
		t.Errorf("liveness = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestReadinessReportsTheFailingCheck(t *testing.T) {
	t.Parallel()

	health := observability.NewHealth()
	health.Register("wallet", func(context.Context) error {
		return errors.New("no identity established")
	})
	health.Register("database", func(context.Context) error { return nil })

	recorder := httptest.NewRecorder()
	health.ReadyHandler().ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("readiness = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}

	var body struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"checks"`
	}

	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the probe body: %v", err)
	}

	// The point of the body is naming what is wrong, not just failing.
	if got := body.Checks["wallet"].Error; !strings.Contains(got, "no identity") {
		t.Errorf("wallet error = %q, want it to name the cause", got)
	}

	if got := body.Checks["database"].Status; got != "ok" {
		t.Errorf("database status = %q, want ok", got)
	}
}

func TestReadinessPassesWithNoChecks(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	observability.NewHealth().ReadyHandler().
		ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))

	if recorder.Code != http.StatusOK {
		t.Errorf("readiness = %d, want %d", recorder.Code, http.StatusOK)
	}
}

// TestReadinessBoundsASlowCheck pins the timeout: a wedged dependency must not
// hold the probe open, or the kubelet's own timeout becomes the only limit.
func TestReadinessBoundsASlowCheck(t *testing.T) {
	t.Parallel()

	health := observability.NewHealth()
	health.Register("wedged", func(ctx context.Context) error {
		<-ctx.Done()

		//nolint:wrapcheck // the context error is exactly what the check means
		return ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, ready := health.Run(ctx)
	if ready {
		t.Error("Run() reported ready with a wedged check")
	}

	if _, ok := results["wedged"]; !ok {
		t.Error("Run() dropped the wedged check from the results")
	}
}

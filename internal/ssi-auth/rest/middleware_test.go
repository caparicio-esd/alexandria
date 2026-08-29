package rest_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/gin-gonic/gin"
)

// TestAccessLogLevelFollowsTheStatus pins the severity mapping. A failure that
// logs at INFO is a failure nobody alerts on and nobody sees while scanning.
func TestAccessLogLevelFollowsTheStatus(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	cases := map[string]struct {
		status int
		want   string
	}{
		"success":      {status: http.StatusOK, want: "INFO"},
		"client error": {status: http.StatusPreconditionFailed, want: "WARN"},
		"server error": {status: http.StatusInternalServerError, want: "ERROR"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			logger := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))

			engine := gin.New()
			engine.Use(rest.AccessLog(logger))
			engine.GET("/probe", func(c *gin.Context) { c.Status(tc.status) })

			engine.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/probe", nil))

			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatalf("decoding the record: %v\n%s", err, out.String())
			}

			if got := record["level"]; got != tc.want {
				t.Errorf("level = %v, want %v", got, tc.want)
			}

			if got := record["status"]; got != float64(tc.status) {
				t.Errorf("status = %v, want %d", got, tc.status)
			}
		})
	}
}

// TestAccessLogCarriesTheCause: a refusal must say what was refused, or the log
// records that something failed and nothing about why.
func TestAccessLogCarriesTheCause(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	var out bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&out, nil))

	engine := gin.New()
	engine.Use(rest.AccessLog(logger))
	engine.GET("/probe", func(c *gin.Context) {
		_ = c.Error(http.ErrNotSupported)
		c.Status(http.StatusBadRequest)
	})

	engine.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/probe", nil))

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("decoding the record: %v\n%s", err, out.String())
	}

	if record["err"] == nil {
		t.Errorf("record carries no cause: %s", out.String())
	}
}

// TestAccessLogUsesTheRouteTemplate: logging the filled-in path would put every
// identifier into the index and give each one its own series.
func TestAccessLogUsesTheRouteTemplate(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	var out bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&out, nil))

	engine := gin.New()
	engine.Use(rest.AccessLog(logger))
	engine.GET("/wallet/did/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	engine.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/wallet/did/did:jwk:secret", nil))

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("decoding the record: %v", err)
	}

	if got, want := record["route"], "/wallet/did/:id"; got != want {
		t.Errorf("route = %v, want %v", got, want)
	}
}

// TestAccessLogKeepsProbesQuiet: an orchestrator polls these every few seconds,
// and a readiness probe reporting 503 while a dependency starts is working as
// designed. Logging that as an error every poll trains everyone to ignore
// errors.
func TestAccessLogKeepsProbesQuiet(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	var out bytes.Buffer

	// Info threshold: a debug record must not appear at all.
	logger := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo}))

	engine := gin.New()
	engine.Use(rest.AccessLog(logger))
	engine.GET("/readyz", func(c *gin.Context) { c.Status(http.StatusServiceUnavailable) })

	engine.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))

	if out.Len() != 0 {
		t.Errorf("probe logged at info: %s", out.String())
	}
}

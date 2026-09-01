package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/httpapi"
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/gin-gonic/gin"
)

// TestProbesAreMountedAtTheRoot pins where the probes live. They must not drift
// under a module prefix: a kubelet is configured with a fixed path, and moving
// them silently turns every probe into a 404, which reads as a dead node.
func TestProbesAreMountedAtTheRoot(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	health := observability.NewHealth()
	health.Register("wallet", func(context.Context) error { return errors.New("no identity") })

	engine := gin.New()
	httpapi.NewRouter(health, nil, rest.NewCoreRouter(rest.NewWalletRouter(nil))).Register(engine)

	cases := map[string]int{
		"/healthz": http.StatusOK,
		// A failing dependency takes the node out of the balancer, and only
		// readiness reflects it.
		"/readyz": http.StatusServiceUnavailable,
	}

	for path, want := range cases {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))

			if recorder.Code != want {
				t.Errorf("GET %s = %d, want %d", path, recorder.Code, want)
			}
		})
	}
}

// TestModuleRoutesStayUnderTheirPrefix: the root router adds process routes, it
// does not move the module's own.
func TestModuleRoutesStayUnderTheirPrefix(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	httpapi.NewRouter(observability.NewHealth(), nil,
		rest.NewCoreRouter(rest.NewWalletRouter(nil))).Register(engine)

	mounted := make(map[string]bool)
	for _, route := range engine.Routes() {
		mounted[route.Path] = true
	}

	for _, path := range []string{
		"/healthz",
		"/readyz",
		httpapi.APIPrefix + "/ssi-auth/wallet/did",
		// Fixed by specification at the root of the origin: versioning it
		// would make it unresolvable.
		"/.well-known/did.json",
	} {
		if !mounted[path] {
			t.Errorf("route %s is not mounted", path)
		}
	}
}

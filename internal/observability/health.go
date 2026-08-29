package observability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"
)

// checkTimeout bounds a single readiness check, so one wedged dependency cannot
// hold the probe open until the kubelet's own timeout fires.
const checkTimeout = 3 * time.Second

// Check reports whether a dependency is usable right now. A nil error means
// ready; the error text is shown in the probe response, so write it for the
// operator reading it at three in the morning.
type Check func(ctx context.Context) error

// Health answers the two probes, which mean different things and must not be
// collapsed into one:
//
//   - Liveness asks whether the process is a lost cause. A failure means
//     restart me, so it must not depend on anything external — a wallet outage
//     restarting every replica in a loop makes an incident worse.
//   - Readiness asks whether the process can serve traffic right now. A failure
//     means take me out of the load balancer and leave me running.
type Health struct {
	mu     sync.RWMutex
	checks map[string]Check
}

// NewHealth builds an empty registry.
func NewHealth() *Health {
	return &Health{checks: make(map[string]Check)}
}

// Register adds a readiness check under a name. Registering the same name twice
// replaces the check.
func (h *Health) Register(name string, check Check) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.checks[name] = check
}

// CheckResult is one dependency's verdict, as it appears in the probe body and
// as Run reports it to a caller that wants to act on the detail.
type CheckResult struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// probeResponse is the body both probes answer with.
type probeResponse struct {
	Status string                 `json:"status"`
	Checks map[string]CheckResult `json:"checks,omitempty"`
}

// LiveHandler answers the liveness probe. It deliberately checks nothing: if
// this handler runs at all, the process is alive.
func (h *Health) LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, probeResponse{Status: "ok"})
	})
}

// ReadyHandler answers the readiness probe: 200 when every check passes, 503
// with the offending names when they do not.
func (h *Health) ReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results, ready := h.Run(r.Context())

		status := http.StatusOK
		summary := "ok"

		if !ready {
			status = http.StatusServiceUnavailable
			summary = "unavailable"
		}

		writeJSON(w, status, probeResponse{Status: summary, Checks: results})
	})
}

// Run evaluates every check and reports whether all of them passed.
//
// The checks run concurrently: readiness is polled often, and a serial sweep
// would add up the latency of every dependency on every poll.
func (h *Health) Run(ctx context.Context) (map[string]CheckResult, bool) {
	// Name and check travel together. Keeping them in two slices and sorting
	// one of them is how a result gets attributed to the wrong dependency.
	type named struct {
		name  string
		check Check
	}

	h.mu.RLock()
	checks := make([]named, 0, len(h.checks))

	for name, check := range h.checks {
		checks = append(checks, named{name: name, check: check})
	}
	h.mu.RUnlock()

	sort.Slice(checks, func(i, j int) bool { return checks[i].name < checks[j].name })

	errs := make([]error, len(checks))

	var wait sync.WaitGroup

	for i, entry := range checks {
		wait.Add(1)

		go func() {
			defer wait.Done()

			checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
			defer cancel()

			errs[i] = entry.check(checkCtx)
		}()
	}

	wait.Wait()

	results := make(map[string]CheckResult, len(checks))
	ready := true

	for i, entry := range checks {
		if errs[i] != nil {
			ready = false
			results[entry.name] = CheckResult{Status: "failing", Error: errs[i].Error()}

			continue
		}

		results[entry.name] = CheckResult{Status: "ok"}
	}

	return results, ready
}

// writeJSON renders a probe response.
func writeJSON(w http.ResponseWriter, status int, body probeResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Nothing useful is left to do with a write failure on a probe: the client
	// is already gone.
	_ = json.NewEncoder(w).Encode(body)
}

// ErrNotReady is the error a check returns when a dependency is simply not
// there yet, as opposed to broken.
var ErrNotReady = errors.New("not ready")

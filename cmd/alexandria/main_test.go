package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// stubWallet stands up a Fafnir that answers the startup handshake, and points
// the configuration at it through the environment override.
//
// It doubles as proof that the override works end to end: the deployment file
// names port 7002, and nothing edits the file.
func stubWallet(t *testing.T) {
	t.Helper()

	payload, err := os.ReadFile("testdata/dids-default.json")
	if err != nil {
		t.Fatalf("reading stub payload: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dids/default" {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		if _, err := w.Write(payload); err != nil {
			t.Errorf("writing stub response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("splitting stub address %q: %v", server.URL, err)
	}

	t.Setenv("ALEXANDRIA_WALLET_CONFIG_API_HTTP_URL", host)
	t.Setenv("ALEXANDRIA_WALLET_CONFIG_API_HTTP_PORT", port)
}

// TestRunLinksThenServes walks the whole startup: load, link, serve, shut down.
//
// The deadline rather than an explicit cancel is what ends it. Cancelling from
// the stub handler would race the client still reading the response body, and a
// cancelled request would look like a wallet failure. t.Setenv rules out
// t.Parallel here.
func TestRunLinksThenServes(t *testing.T) {
	stubWallet(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var out bytes.Buffer

	if err := run(ctx, []string{"-config", "testdata/config.yaml"}, &out); err != nil {
		t.Fatalf("run() = %v", err)
	}

	for _, want := range []string{"alexandria dev", "ssi-auth", "did:jwk:", "listening"} {
		if got := out.String(); !strings.Contains(got, want) {
			t.Errorf("run() wrote %q, want it to contain %q", got, want)
		}
	}
}

// TestRunComesUpWithoutAWallet pins the other half of the handshake: past the
// startup budget the node serves anyway, and says so, rather than refusing to
// start and turning a wallet outage into a restart loop.
//
// The budget is cut to a few hundred milliseconds through the environment, so
// the test does not sit out the ten-second default.
func TestRunComesUpWithoutAWallet(t *testing.T) {
	t.Setenv("ALEXANDRIA_WALLET_CONFIG_STARTUP_LINK_TIMEOUT", "200ms")
	// A port nothing is listening on.
	t.Setenv("ALEXANDRIA_WALLET_CONFIG_API_HTTP_PORT", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var out bytes.Buffer

	if err := run(ctx, []string{"-config", "testdata/config.yaml"}, &out); err != nil {
		t.Fatalf("run() = %v, want the node to come up anyway", err)
	}

	if got := out.String(); !strings.Contains(got, "not linked within the startup budget") {
		t.Errorf("run() wrote %q, want it to report the unlinked wallet", got)
	}

	if got := out.String(); !strings.Contains(got, "listening") {
		t.Errorf("run() wrote %q, want it to serve anyway", got)
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	if err := run(context.Background(), []string{"-x"}, &out); err == nil {
		t.Fatal("run() accepted an unknown flag, want an error")
	}
}

func TestRunReportsMissingConfig(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	err := run(context.Background(), []string{"-config", "testdata/nope.yaml"}, &out)
	if err == nil {
		t.Fatal("run() with a missing config succeeded, want an error")
	}

	if !strings.Contains(err.Error(), "loading config") {
		t.Errorf("run() error = %v, want it to name the config load", err)
	}
}

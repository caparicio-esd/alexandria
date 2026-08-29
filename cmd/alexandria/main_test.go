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

	t.Setenv("ALEXANDRIA_SSI_AUTH_WALLET_CONFIG_API_HTTP_URL", host)
	t.Setenv("ALEXANDRIA_SSI_AUTH_WALLET_CONFIG_API_HTTP_PORT", port)
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

	for _, want := range []string{"alexandria dev", "linked", "did:jwk:", "listening"} {
		if got := out.String(); !strings.Contains(got, want) {
			t.Errorf("run() wrote %q, want it to contain %q", got, want)
		}
	}
}

// TestRunGivesUpOnAnAbsentWallet pins the other half of the handshake: the node
// must not come up without an identity, and it must say why.
func TestRunGivesUpOnAnAbsentWallet(t *testing.T) {
	t.Parallel()

	// Already cancelled, so the retry loop reports the failure on its first
	// pass instead of waiting out linkTimeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out bytes.Buffer

	err := run(ctx, []string{"-config", "testdata/config.yaml"}, &out)
	if err == nil {
		t.Fatal("run() came up without a wallet, want an error")
	}

	if !strings.Contains(err.Error(), "linking wallet") {
		t.Errorf("run() error = %v, want it to name the wallet handshake", err)
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

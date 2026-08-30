package config_test

import (
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/config"
)

// TestDSNEscapesCredentials: a password with an "@" in it must not be able to
// move the host.
func TestDSNEscapesCredentials(t *testing.T) {
	t.Parallel()

	db := config.Database{
		Driver:   config.DriverPostgres,
		Host:     "127.0.0.1",
		Port:     "1500",
		User:     "alexandria",
		Password: "p@ss/word",
		Name:     "alexandria",
	}

	got := db.DSN()
	want := "postgres://alexandria:p%40ss%2Fword@127.0.0.1:1500/alexandria"

	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

// TestRedactedHidesThePassword: a connection string in a log line is a password
// in a log aggregator, read by more people than the database ever was.
func TestRedactedHidesThePassword(t *testing.T) {
	t.Parallel()

	db := config.Database{
		Driver:   config.DriverPostgres,
		Host:     "127.0.0.1",
		Port:     "1500",
		User:     "alexandria",
		Password: "hunter2",
		Name:     "alexandria",
	}

	if got := db.Redacted(); strings.Contains(got, "hunter2") {
		t.Errorf("Redacted() = %q, want the password gone", got)
	}

	if got := db.Redacted(); !strings.Contains(got, "alexandria@127.0.0.1:1500") {
		t.Errorf("Redacted() = %q, want it to still name the server", got)
	}
}

// TestPostgresNeedsCredentials: a driver that authenticates must say as whom.
// The password is not required — a server set up for trust or peer
// authentication takes none, and demanding one would make that deployment
// impossible to express.
func TestPostgresNeedsCredentials(t *testing.T) {
	t.Parallel()

	doc := func(db string) string {
		return `
common_config:
  hosts: {http: {protocol: http, url: 127.0.0.1, port: '1200'}}
  db: ` + db + `
  api: {version: v1, openapi_path: ./openapi.json}
  connection: {is_local: true, is_prod: false, is_vault_real: false, has_tls_proxy: false}
wallet_config:
  wallet: Fafnir
  api: {http: {protocol: http, url: 127.0.0.1, port: '7002'}}
client_config: {class_id: Provider, display: null}
verify_req_config: {is_cert_allowed: false, auto_approve_cert: false, vcs_requested: []}
did_config: {type: Jwk}
gaia_config: null
`
	}

	_, err := config.Decode(strings.NewReader(doc("{db_type: Postgres, url: 127.0.0.1, port: '1500'}")))
	if err == nil {
		t.Fatal("Decode() accepted postgres with no credentials, want an error")
	}

	for _, want := range []string{"common_config.db.user", "common_config.db.name"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}

	// No password is legitimate; no user is not.
	const trustAuth = "{db_type: Postgres, url: 127.0.0.1, port: '1500', user: alexandria, name: alexandria}"

	if _, err := config.Decode(strings.NewReader(doc(trustAuth))); err != nil {
		t.Errorf("Decode() rejected a passwordless deployment: %v", err)
	}
}

// TestPoolDefaults: a pool with no ceiling is how a burst turns into "too many
// clients already" for everything else sharing the server.
func TestPoolDefaults(t *testing.T) {
	t.Parallel()

	const doc = `
common_config:
  hosts: {http: {protocol: http, url: 127.0.0.1, port: '1200'}}
  db: {db_type: Postgres, url: 127.0.0.1, port: '1500', user: alexandria, password: alexandria, name: alexandria}
  api: {version: v1, openapi_path: ./openapi.json}
  connection: {is_local: true, is_prod: false, is_vault_real: false, has_tls_proxy: false}
wallet_config:
  wallet: Fafnir
  api: {http: {protocol: http, url: 127.0.0.1, port: '7002'}}
client_config: {class_id: Provider, display: null}
verify_req_config: {is_cert_allowed: false, auto_approve_cert: false, vcs_requested: []}
did_config: {type: Jwk}
gaia_config: null
`

	cfg, err := config.Decode(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Decode() = %v", err)
	}

	if got := cfg.Common.DB.MaxConns; got != 10 {
		t.Errorf("MaxConns = %d, want the default 10", got)
	}

	if got := cfg.Common.DB.ConnMaxLifetime.String(); got != "1h0m0s" {
		t.Errorf("ConnMaxLifetime = %s, want the default 1h", got)
	}

	if !cfg.Common.DB.IsPostgres() {
		t.Error("IsPostgres() = false for driver postgres")
	}
}

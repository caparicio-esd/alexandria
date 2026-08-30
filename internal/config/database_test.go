package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/caparicio-esd/alexandria/internal/config"
)

func TestSecretsFromEnv(t *testing.T) {
	t.Setenv(config.EnvDBUser, "alexandria")
	t.Setenv(config.EnvDBPassword, "p@ss/word")
	t.Setenv(config.EnvDBName, "alexandria")

	secrets, err := config.SecretsFromEnv()
	if err != nil {
		t.Fatalf("SecretsFromEnv() = %v", err)
	}

	if secrets.Password != "p@ss/word" {
		t.Errorf("Password = %q, want the raw value", secrets.Password)
	}
}

// TestSecretsFromEnvNamesEveryMissingVariable: an operator setting up a
// deployment would rather see the three that are absent than discover them one
// restart at a time.
func TestSecretsFromEnvNamesEveryMissingVariable(t *testing.T) {
	t.Setenv(config.EnvDBUser, "")
	t.Setenv(config.EnvDBPassword, "")
	t.Setenv(config.EnvDBName, "")

	_, err := config.SecretsFromEnv()
	if err == nil {
		t.Fatal("SecretsFromEnv() succeeded with nothing set, want an error")
	}

	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}

	for _, want := range []string{config.EnvDBUser, config.EnvDBPassword, config.EnvDBName} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// TestPoolDefaults: a pool with no ceiling is how a burst turns into "too many
// clients already" for everything else sharing the server.
func TestPoolDefaults(t *testing.T) {
	t.Parallel()

	const doc = `
common_config:
  hosts: {http: {protocol: http, url: 127.0.0.1, port: '1200'}}
  db: {db_type: Postgres, url: 127.0.0.1, port: '1400'}
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

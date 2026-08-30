package config_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

// TestLoadFixtures runs the parser against the four node configurations, which
// carry the values of the real eunomia deployments: null endpoints, an optional
// gRPC transport, an optional admin seed and an optional Gaia-X description.
func TestLoadFixtures(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		path      string
		classID   string
		nodeURL   string
		walletURL string
		dbPort    string
		hasGRPC   bool
		hasSeed   bool
		hasGaia   bool
	}{
		"consumer": {
			path:      "testdata/consumer.yaml",
			classID:   "Consumer",
			nodeURL:   "http://127.0.0.1:1100",
			walletURL: "http://127.0.0.1:7001",
			dbPort:    "1300",
			hasSeed:   true,
			hasGaia:   true,
		},
		"consumer-dev": {
			path:      "testdata/consumer-dev.yaml",
			classID:   "Consumer",
			nodeURL:   "http://127.0.0.1:1100",
			walletURL: "http://127.0.0.1:7001",
			dbPort:    "1300",
			hasGaia:   true,
		},
		"provider": {
			path:      "testdata/provider.yaml",
			classID:   "Provider",
			nodeURL:   "http://127.0.0.1:1200",
			walletURL: "http://127.0.0.1:7002",
			dbPort:    "1400",
			hasGRPC:   true,
			hasSeed:   true,
		},
		"provider-dev": {
			path:      "testdata/provider-dev.yaml",
			classID:   "Provider",
			nodeURL:   "http://127.0.0.1:1200",
			walletURL: "http://127.0.0.1:7002",
			dbPort:    "1400",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(tc.path)
			if err != nil {
				t.Fatalf("Load(%q) = %v", tc.path, err)
			}

			if got := cfg.Client.ClassID; got != tc.classID {
				t.Errorf("Client.ClassID = %q, want %q", got, tc.classID)
			}

			if got := cfg.Common.Hosts.HTTP.URL(); got != tc.nodeURL {
				t.Errorf("node URL = %q, want %q", got, tc.nodeURL)
			}

			walletURL, err := cfg.Wallet.APIURL(config.HostHTTP)
			if err != nil {
				t.Fatalf("Wallet.APIURL() = %v", err)
			}

			if walletURL != tc.walletURL {
				t.Errorf("Wallet.APIURL() = %q, want %q", walletURL, tc.walletURL)
			}

			// "Postgres" in the file, canonicalised on the way in.
			if got := cfg.Common.DB.Driver; got != config.DriverPostgres {
				t.Errorf("DB.Driver = %q, want %q", got, config.DriverPostgres)
			}

			if got := cfg.Common.DB.Port; got != tc.dbPort {
				t.Errorf("DB.Port = %q, want %q", got, tc.dbPort)
			}

			// "Fafnir" in the file, likewise.
			if got := cfg.Wallet.Kind; got != config.KindFafnir {
				t.Errorf("Wallet.Kind = %q, want %q", got, config.KindFafnir)
			}

			// "Jwk" in the file; wallet.ParseMethod is case-insensitive.
			if got := cfg.Did.Method; got != wallet.MethodJwk {
				t.Errorf("Did.Method = %q, want %q", got, wallet.MethodJwk)
			}

			if got := cfg.Common.API.Prefix(); got != "/api/v1" {
				t.Errorf("API.Prefix() = %q, want /api/v1", got)
			}

			if got := len(cfg.Verify.VCsRequested); got != 1 {
				t.Errorf("len(VCsRequested) = %d, want 1", got)
			}

			// grpc: null must decode to a nil endpoint, not an empty one.
			_, err = cfg.Common.Hosts.Endpoint(config.HostGRPC)
			if tc.hasGRPC && err != nil {
				t.Errorf("Endpoint(grpc) = %v, want the configured endpoint", err)
			}

			if !tc.hasGRPC && !errors.Is(err, config.ErrNoSuchHost) {
				t.Errorf("Endpoint(grpc) error = %v, want ErrNoSuchHost", err)
			}

			if got := cfg.Common.AdminSeed != nil; got != tc.hasSeed {
				t.Errorf("AdminSeed present = %t, want %t", got, tc.hasSeed)
			}

			// gaia_config: null must not leave a zero-valued description behind.
			if got := cfg.Gaia != nil; got != tc.hasGaia {
				t.Errorf("Gaia present = %t, want %t", got, tc.hasGaia)
			}

			// None of the fixtures carries an observability section, so this
			// is the defaults landing: a file written before a setting existed
			// still has to come up with sensible behaviour.
			if got, want := cfg.Observability.Port, "2112"; got != want {
				t.Errorf("Observability.Port = %q, want %q", got, want)
			}

			if got, want := cfg.Wallet.StartupLinkTimeout, 10*time.Second; got != want {
				t.Errorf("StartupLinkTimeout = %s, want %s", got, want)
			}
		})
	}
}

// TestGaiaDetail pins the nested transcription, the deepest part of the file.
func TestGaiaDetail(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load("testdata/consumer.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	if cfg.Gaia == nil {
		t.Fatal("Gaia = nil, want the consumer participant description")
	}

	person := cfg.Gaia.LegalPerson

	if got, want := person.Name, "EunomiaConsumer"; got != want {
		t.Errorf("LegalPerson.Name = %q, want %q", got, want)
	}

	if got, want := person.RegistrationNumber.Value, "VATES-123456789"; got != want {
		t.Errorf("RegistrationNumber.Value = %q, want %q", got, want)
	}

	// The field is commented out in the file, so it must stay empty rather
	// than pick anything up from its neighbours.
	if got := person.RegistrationNumber.SubdivisionCountryCode; got != "" {
		t.Errorf("SubdivisionCountryCode = %q, want empty", got)
	}

	if got, want := person.LegalAddress.PostalCode, "28040"; got != want {
		t.Errorf("LegalAddress.PostalCode = %q, want %q", got, want)
	}
}

// TestNullInternalPort covers the file's `internal_port: null`: with no
// remapping, the cluster address falls back to the published port.
func TestNullInternalPort(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load("testdata/provider.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	endpoint := cfg.Common.Hosts.HTTP

	if endpoint.InternalPort != "" {
		t.Errorf("InternalPort = %q, want empty for a null", endpoint.InternalPort)
	}

	if got, want := endpoint.InternalURL(), "http://127.0.0.1:1200"; got != want {
		t.Errorf("InternalURL() = %q, want %q", got, want)
	}
}

func TestDecodeRejects(t *testing.T) {
	t.Parallel()

	const base = `
common_config:
  hosts: {http: {protocol: http, url: 127.0.0.1, port: '1100', internal_port: null}, grpc: null, graphql: null}
  db: {db_type: Postgres, url: 127.0.0.1, port: '1300'}
  api: {version: v1, openapi_path: ./openapi.json}
  connection: {is_local: true, is_prod: false, is_vault_real: false, has_tls_proxy: false}
wallet_config:
  wallet: Fafnir
  api: {http: {protocol: http, url: 127.0.0.1, port: '7001'}, grpc: null, graphql: null}
client_config: {class_id: Consumer, display: null}
verify_req_config: {is_cert_allowed: false, auto_approve_cert: false, vcs_requested: [DataSpaceParticipant]}
gaia_config: null
`

	cases := map[string]string{
		"unknown key":               base + "nonsense: true\ndid_config: {type: Jwk}\n",
		"unknown did method":        base + "did_config: {type: ion}\n",
		"did:web without a domain":  base + "did_config: {type: Web}\n",
		"did:jwk carrying a domain": base + "did_config: {type: Jwk, domain: example.org}\n",
		"unsupported wallet": strings.Replace(
			base+"did_config: {type: Jwk}\n", "wallet: Fafnir", "wallet: WaltId", 1),
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := config.Decode(strings.NewReader(doc)); err == nil {
				t.Fatal("Decode() succeeded, want an error")
			}
		})
	}
}

func TestValidateReportsEveryFailure(t *testing.T) {
	t.Parallel()

	const doc = `
common_config:
  hosts: {http: {protocol: "", url: ""}}
  db: {db_type: Postgres, url: "", port: '1300'}
  api: {version: "", openapi_path: ""}
  connection: {is_local: true, is_prod: false, is_vault_real: false, has_tls_proxy: false}
wallet_config:
  wallet: Fafnir
  api: {http: {protocol: http, url: 127.0.0.1, port: '7001'}}
client_config: {class_id: Consumer, display: null}
verify_req_config: {is_cert_allowed: false, auto_approve_cert: false, vcs_requested: []}
did_config: {type: Web}
gaia_config: null
`

	_, err := config.Decode(strings.NewReader(doc))
	if err == nil {
		t.Fatal("Decode() succeeded, want an error")
	}

	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}

	// One restart, every complaint.
	for _, want := range []string{
		"common_config.api.version",
		"common_config.db.url",
		"common_config.hosts.http.protocol",
		"common_config.hosts.http.url",
		"did_config.domain",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

// TestEnvOverride covers the reason Viper is here at all: an operator can point
// a container at a different wallet without editing the deployment file.
//
// It does not call t.Parallel: t.Setenv and parallel tests are incompatible.
func TestEnvOverride(t *testing.T) {
	t.Setenv("ALEXANDRIA_WALLET_CONFIG_API_HTTP_PORT", "9999")

	cfg, err := config.Load("testdata/consumer.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	got, err := cfg.Wallet.APIURL(config.HostHTTP)
	if err != nil {
		t.Fatalf("Wallet.APIURL() = %v", err)
	}

	if want := "http://127.0.0.1:9999"; got != want {
		t.Errorf("Wallet.APIURL() = %q, want %q", got, want)
	}
}

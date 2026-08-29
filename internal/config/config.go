// Package config loads the node configuration from the deployment's YAML
// document.
//
// The file is shared across every service of the dataspace deployment —
// catalog, contracts, transfer, gateway and this one — so loading it means
// picking one section out of a larger document. Only the ssi_auth section is
// modelled here; the siblings are absorbed and ignored, which lets one
// operator-maintained file drive services written in different languages.
//
// It is a driven adapter like any other: it knows the file format, and it hands
// the composition root plain values. The domain never imports it, and no type
// in here is passed wholesale into a use case — main picks out what each
// constructor needs, so a service cannot reach for configuration it did not
// declare a dependency on.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

// ErrInvalid reports that the configuration is unusable. Every validation
// failure wraps it, so a caller can tell a bad file from a missing one with a
// single errors.Is.
var ErrInvalid = errors.New("invalid configuration")

// invalid is the shorthand used across the validators. The field is named in
// dotted YAML path form so the message points at the line to fix.
func invalid(field, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, field, reason)
}

// sectionKey is the section a shared deployment file files this node under.
const sectionKey = "ssi_auth"

// document is a shared deployment file: several services in one YAML, of which
// only ssi_auth belongs to this node.
//
// Only ssi_auth is modelled. Everything else — the other services, and the
// top-level anchor definitions the file uses to avoid repeating itself — lands
// in Rest and is discarded. The inline map is what makes that possible while
// strict field checking still applies inside the section we do model: without
// it, the decoder would reject the file for naming a service we do not run.
type document struct {
	SSIAuth Config         `mapstructure:"ssi_auth"`
	Rest    map[string]any `mapstructure:",remain"`
}

// Config is the ssi_auth section: everything this node needs to run.
//
// Secrets are largely absent by design — key material comes from Vault and
// database credentials from the environment — with the exception of the admin
// seed, which the deployment file carries for local runs. See AdminSeed.
type Config struct {
	Common Common `mapstructure:"common_config"`
	// Observability is optional: a deployment file that omits it gets the
	// defaults set on the loader, which are the ones a container wants.
	Observability Observability `mapstructure:"observability"`
	Wallet        Wallet        `mapstructure:"wallet_config"`
	Client        Client        `mapstructure:"client_config"`
	Verify        Verify        `mapstructure:"verify_req_config"`
	Did           Did           `mapstructure:"did_config"`
	// Gaia is nil on a deployment that publishes no Gaia-X participant
	// description, which the file spells as `gaia_config: null`.
	Gaia *Gaia `mapstructure:"gaia_config"`

	// source is the document this was read from. It is unexported and has no
	// mapstructure tag on purpose: it describes the load, not the deployment,
	// so a file that tried to set it would be rejected like any other unknown
	// key.
	source string
}

// Source names the document this configuration was read from, for the operator
// asking which file the process actually picked up.
func (c *Config) Source() string {
	return c.source
}

// Load reads and validates the ssi_auth section of the deployment file at path.
func Load(path string) (*Config, error) {
	loader := newLoader()
	loader.SetConfigFile(path)

	if err := loader.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	cfg, err := unmarshal(loader)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}

	cfg.source = path

	return cfg, nil
}

// Discover looks for a "config" document in dirs, in order, and loads the first
// one it finds. The extension is left to Viper, so config.yaml, config.yml and
// config.json all match.
func Discover(dirs ...string) (*Config, error) {
	loader := newLoader()
	loader.SetConfigName("config")

	for _, dir := range dirs {
		loader.AddConfigPath(dir)
	}

	if err := loader.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("discovering config in %v: %w", dirs, err)
	}

	cfg, err := unmarshal(loader)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", loader.ConfigFileUsed(), err)
	}

	cfg.source = loader.ConfigFileUsed()

	return cfg, nil
}

// Decode parses and validates a deployment document from a reader.
//
// It is separate from Load so tests can feed a literal string, and so a caller
// embedding the document elsewhere is not forced through the filesystem.
func Decode(r io.Reader) (*Config, error) {
	loader := newLoader()
	loader.SetConfigType("yaml")

	if err := loader.ReadConfig(r); err != nil {
		return nil, fmt.Errorf("decoding yaml: %w", err)
	}

	cfg, err := unmarshal(loader)
	if err != nil {
		return nil, err
	}

	cfg.source = "<reader>"

	return cfg, nil
}

// EnvPrefix is the prefix of the environment variables that override the file.
//
// The rest of the variable name is the dotted path to the setting, upper-cased
// with underscores, so the wallet port is
// ALEXANDRIA_SSI_AUTH_WALLET_CONFIG_API_HTTP_PORT.
const EnvPrefix = "ALEXANDRIA"

// newLoader builds a Viper instance with the environment wired in.
//
// A fresh instance rather than the package-level singleton: a global would make
// two configs in one process impossible, and would leak between tests.
func newLoader() *viper.Viper {
	loader := viper.New()
	loader.SetEnvPrefix(EnvPrefix)
	// Viper matches environment variables by the flattened key, so the dots of
	// the config path have to become underscores.
	loader.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	loader.AutomaticEnv()

	return loader
}

// applyDefaults registers the fallbacks under the prefix the document uses.
//
// Defaults live on the loader rather than in the structs so a deployment file
// written before a setting existed keeps working and still gets sensible
// behaviour. Viper folds them into the document it unmarshals.
//
// They are applied after the document is read, not before: whether the file is
// nested is exactly what a default would otherwise make impossible to tell,
// since a default on "…" makes that key look present in every file.
func applyDefaults(loader *viper.Viper, prefix string) {
	for key, value := range map[string]any{
		"observability.log_level":            "info",
		"observability.log_format":           string(LogFormatAuto),
		"observability.metrics":              true,
		"observability.pprof":                false,
		"observability.port":                 "2112",
		"wallet_config.startup_link_timeout": "10s",
	} {
		loader.SetDefault(prefix+key, value)
	}
}

// unmarshal projects a loaded document onto Config and validates it.
//
// Two layouts are accepted, because the same parser serves two kinds of file:
//
//   - Flat, where the document is this node's configuration and nothing else.
//     That is what a file written for alexandria alone looks like.
//   - Nested under "ssi_auth", which is how the shared dataspace deployment
//     file — the one catalog, contracts, transfer and gateway also read — files
//     this node's section.
//
// The layout is inferred from whether the section is present, so neither kind
// of file needs a marker saying which it is.
func unmarshal(loader *viper.Viper) (*Config, error) {
	nested := loader.Get(sectionKey) != nil

	prefix := ""
	if nested {
		prefix = sectionKey + "."
	}

	applyDefaults(loader, prefix)

	// ErrorUnused is what makes a typo fatal. Viper does not offer strict
	// decoding of its own, so it is set on the mapstructure decoder underneath:
	// a key nobody consumed is a key the operator got wrong.
	strict := func(cfg *mapstructure.DecoderConfig) {
		cfg.ErrorUnused = true
	}

	if !nested {
		var cfg Config

		if err := loader.Unmarshal(&cfg, strict); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}

		if err := cfg.Validate(); err != nil {
			return nil, err
		}

		return &cfg, nil
	}

	// In a shared file the sibling services stay exempt from strict decoding,
	// because document.Rest consumes them.
	var doc document

	if err := loader.Unmarshal(&doc, strict); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	if err := doc.SSIAuth.Validate(); err != nil {
		return nil, err
	}

	return &doc.SSIAuth, nil
}

// Validate checks every section and canonicalises the spellings it accepts.
//
// The failures are joined rather than returned one at a time: an operator
// fixing a config file would rather see the four things that are wrong than
// discover them across four restarts.
func (c *Config) Validate() error {
	return errors.Join(
		c.Common.API.Validate(),
		c.Common.DB.Validate(),
		c.Common.Hosts.Validate("common_config.hosts"),
		c.Did.Validate(),
		c.Observability.Validate(),
		c.Wallet.Validate(),
	)
}

// ===== Common ================================================================

// Common is the block every service of the deployment shares. Each one decodes
// its own copy: the file repeats it through a YAML anchor.
type Common struct {
	Hosts      Hosts      `mapstructure:"hosts"`
	DB         Database   `mapstructure:"db"`
	API        API        `mapstructure:"api"`
	Connection Connection `mapstructure:"connection"`
	// AdminSeed provisions the first tenant on an empty database. It is absent
	// from any deployment that is not seeded, and it carries a password: a file
	// that sets it is a development file, not one to commit for production.
	AdminSeed *AdminSeed `mapstructure:"admin_seed,omitempty"`
}

// AdminSeed is the initial administrator account.
type AdminSeed struct {
	TenantID string `mapstructure:"tenant_id"`
	Email    string `mapstructure:"email"`
	Password string `mapstructure:"password"`
}

// ===== API ===================================================================

// API describes the surface this node exposes and where its contract lives.
type API struct {
	// Version is the route-dispatch segment, e.g. "v1".
	Version string `mapstructure:"version"`
	// OpenAPIPath points at the OpenAPI document served alongside the API.
	OpenAPIPath string `mapstructure:"openapi_path"`
}

// Validate implements the section contract.
func (a API) Validate() error {
	if a.Version == "" {
		return invalid("common_config.api.version", `must be set, e.g. "v1"`)
	}

	return nil
}

// Prefix is the canonical route prefix, "/api/<version>".
func (a API) Prefix() string {
	return "/api/" + a.Version
}

// OpenAPI reads the OpenAPI document off disk.
//
// The read is deferred to call time rather than done at load: the specification
// is served, not consulted, so a node with a stale path should still start and
// fail only on the route that needs it.
func (a API) OpenAPI() ([]byte, error) {
	if a.OpenAPIPath == "" {
		return nil, invalid("common_config.api.openapi_path", "no OpenAPI document configured")
	}

	doc, err := os.ReadFile(a.OpenAPIPath) //nolint:gosec // operator-supplied path, by design
	if err != nil {
		return nil, fmt.Errorf("reading openapi document %q: %w", a.OpenAPIPath, err)
	}

	return doc, nil
}

// ===== Connection ============================================================

// Connection holds the deployment flags that change how the node talks to the
// world. They are plain booleans on purpose: anything with more than two states
// belongs in a section of its own.
type Connection struct {
	// IsLocal marks a workstation run, where peers resolve over loopback.
	IsLocal bool `mapstructure:"is_local"`
	// IsProd locks down the behaviours that are only safe in development.
	IsProd bool `mapstructure:"is_prod"`
	// IsVaultReal reports whether key material comes from a real Vault or from
	// the in-process mock.
	IsVaultReal bool `mapstructure:"is_vault_real"`
	// HasTLSProxy reports whether TLS is terminated upstream, in which case the
	// node itself serves plain HTTP.
	HasTLSProxy bool `mapstructure:"has_tls_proxy"`
}

// ===== Client ================================================================

// Client is how this node presents itself to the rest of the dataspace.
type Client struct {
	// ClassID is the role the node plays, e.g. "Consumer" or "Provider".
	ClassID string `mapstructure:"class_id"`
	// Display is the optional human-readable name shown to a peer. Nil and
	// empty differ here — an operator setting it to "" is saying something —
	// so it stays a pointer.
	Display *string `mapstructure:"display"`
}

// ===== Verification requirements =============================================

// Verify is the policy applied to inbound credentials.
type Verify struct {
	// IsCertAllowed permits an X.509 certificate as a trust anchor.
	IsCertAllowed bool `mapstructure:"is_cert_allowed"`
	// AutoApproveCert skips the manual approval queue for a valid certificate.
	AutoApproveCert bool `mapstructure:"auto_approve_cert"`
	// VCsRequested lists the credential types a peer must present. They stay
	// strings here: the catalogue of types is a domain concern, and config has
	// no business rejecting a type the domain has not seen yet.
	VCsRequested []string `mapstructure:"vcs_requested"`
}

// ===== Wallet ================================================================

// Kind names the wallet product backing the key material.
type Kind string

// KindFafnir is the Fafnir wallet, reached over its HTTP API.
const KindFafnir Kind = "fafnir"

// Wallet points at the outsourced wallet backing the key material.
type Wallet struct {
	// Kind selects the adapter the composition root wires in.
	Kind Kind `mapstructure:"wallet"`
	// API is the wallet endpoint matrix, one entry per transport.
	API Hosts `mapstructure:"api"`
	// StartupLinkTimeout is how long startup blocks waiting for the wallet
	// before giving up and continuing in the background. A node and its wallet
	// usually come up together, so a short wait catches the common case; past
	// it, readiness is the better place to report the problem.
	StartupLinkTimeout time.Duration `mapstructure:"startup_link_timeout"`
}

// Validate implements the section contract, and canonicalises the product name:
// the deployment file spells it "Fafnir", the constant is lowercase.
func (w *Wallet) Validate() error {
	w.Kind = Kind(strings.ToLower(strings.TrimSpace(string(w.Kind))))

	if w.Kind != KindFafnir {
		return invalid("wallet_config.wallet", fmt.Sprintf("unsupported wallet %q", w.Kind))
	}

	if w.StartupLinkTimeout < 0 {
		return invalid("wallet_config.startup_link_timeout", "must not be negative")
	}

	return w.API.Validate("wallet_config.api")
}

// APIURL resolves the wallet endpoint for a transport.
func (w Wallet) APIURL(transport HostType) (string, error) {
	endpoint, err := w.API.Endpoint(transport)
	if err != nil {
		return "", fmt.Errorf("wallet api: %w", err)
	}

	return endpoint.URL(), nil
}

package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Driver is a supported storage backend.
type Driver string

const (
	// DriverPostgres is PostgreSQL, the production default.
	DriverPostgres Driver = "postgres"
	// DriverMySQL is MySQL or MariaDB.
	DriverMySQL Driver = "mysql"
	// DriverSQLite is an on-disk SQLite file.
	DriverSQLite Driver = "sqlite"
	// DriverMongo is MongoDB.
	DriverMongo Driver = "mongodb"
	// DriverMemory is the ephemeral backend used by tests and by a dry run.
	DriverMemory Driver = "memory"
)

// Database locates the store. It carries no credentials: those arrive at run
// time from the environment or Vault, so this file never holds a password.
type Database struct {
	// Driver is the backend to speak to.
	Driver Driver `mapstructure:"db_type"`
	// Host is the address of the server. Ignored by the memory backend.
	Host string `mapstructure:"url,omitempty"`
	// Port is the port of the server. Ignored by the memory backend.
	Port string `mapstructure:"port,omitempty"`
	// MaxConns caps the pool. A pool with no ceiling is how a burst of traffic
	// turns into "too many clients already" for every other service sharing
	// the server.
	MaxConns int32 `mapstructure:"max_conns,omitempty"`
	// ConnMaxLifetime retires a connection after this long, so a failover or a
	// rotated credential is picked up without a restart.
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime,omitempty"`
}

// IsPostgres reports whether this deployment talks to a real Postgres server.
func (d Database) IsPostgres() bool {
	return d.Driver == DriverPostgres
}

// Database pool defaults, applied when the document says nothing.
const (
	defaultMaxConns        = 10
	defaultConnMaxLifetime = time.Hour
)

// Secrets are the credential halves of a connection string, resolved at run
// time and never read from the configuration file.
type Secrets struct {
	User     string
	Password string
	Name     string
}

// The environment variables carrying the database credentials. They are not
// configuration keys: a password in the document would be a password in the
// repository.
const (
	EnvDBUser     = EnvPrefix + "_DB_USER"
	EnvDBPassword = EnvPrefix + "_DB_PASSWORD"
	EnvDBName     = EnvPrefix + "_DB_NAME"
)

// SecretsFromEnv reads the database credentials from the environment.
//
// Every missing variable is named at once: an operator setting up a deployment
// would rather see the three that are absent than discover them one restart at
// a time.
func SecretsFromEnv() (Secrets, error) {
	secrets := Secrets{
		User:     os.Getenv(EnvDBUser),
		Password: os.Getenv(EnvDBPassword),
		Name:     os.Getenv(EnvDBName),
	}

	missing := make([]string, 0, 3)

	for name, value := range map[string]string{
		EnvDBUser:     secrets.User,
		EnvDBPassword: secrets.Password,
		EnvDBName:     secrets.Name,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)

		return Secrets{}, fmt.Errorf("%w: database credentials: %s must be set",
			ErrInvalid, strings.Join(missing, ", "))
	}

	return secrets, nil
}

// Validate implements the section contract, and canonicalises the driver name:
// the deployment file spells it "Postgres", the constants are lowercase.
//
// The pointer receiver is what lets it normalise in place; the sections that
// only inspect take a value receiver.
func (d *Database) Validate() error {
	d.Driver = Driver(strings.ToLower(strings.TrimSpace(string(d.Driver))))

	if d.MaxConns <= 0 {
		d.MaxConns = defaultMaxConns
	}

	if d.ConnMaxLifetime <= 0 {
		d.ConnMaxLifetime = defaultConnMaxLifetime
	}

	switch d.Driver {
	case DriverMemory:
		return nil
	case DriverPostgres, DriverMySQL, DriverSQLite, DriverMongo:
		if d.Host == "" {
			return invalid("common_config.db.url", "must be set for driver "+string(d.Driver))
		}

		return nil
	default:
		return invalid("common_config.db.db_type", fmt.Sprintf("unknown driver %q", d.Driver))
	}
}

// DSN assembles the connection string handed to the storage layer.
//
// It is built through net/url rather than by formatting a string, so a password
// containing "@", "/" or ":" is percent-encoded instead of silently producing a
// DSN that points somewhere else.
func (d Database) DSN(secrets Secrets) string {
	if d.Driver == DriverMemory {
		return ":memory:"
	}

	dsn := url.URL{
		Scheme: string(d.Driver),
		User:   url.UserPassword(secrets.User, secrets.Password),
		Host:   net.JoinHostPort(d.Host, d.Port),
		Path:   "/" + secrets.Name,
	}

	return dsn.String()
}

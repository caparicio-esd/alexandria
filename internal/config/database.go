package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
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

// Database locates the store and says how to authenticate against it.
//
// The credentials live in the document rather than in a secret store. That is a
// deliberate trade: a deployment renders this file — with Helm, or by mounting
// it into a container — so the password that reaches production is generated
// there and never exists in the repository. The file committed here is a
// development file, and what it holds is a development password.
//
// Any of these can still be overridden from the environment, which is the
// escape hatch when a deployment would rather inject the password than render
// it: ALEXANDRIA_COMMON_CONFIG_DB_PASSWORD.
type Database struct {
	// Driver is the backend to speak to.
	Driver Driver `mapstructure:"db_type"`
	// User is the role to connect as.
	User string `mapstructure:"user,omitempty"`
	// Password authenticates the role. It may be empty where the server is
	// configured for trust or peer authentication.
	Password string `mapstructure:"password,omitempty"`
	// Name is the database to open.
	Name string `mapstructure:"name,omitempty"`
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
		var errs []error

		if d.Host == "" {
			errs = append(errs, invalid("common_config.db.url", "must be set for driver "+string(d.Driver)))
		}

		// The password is not required: a server configured for trust or peer
		// authentication takes none, and demanding one would make that
		// deployment impossible to express.
		if d.User == "" {
			errs = append(errs, invalid("common_config.db.user", "must be set"))
		}

		if d.Name == "" {
			errs = append(errs, invalid("common_config.db.name", "must be set"))
		}

		return errors.Join(errs...)
	default:
		return invalid("common_config.db.db_type", fmt.Sprintf("unknown driver %q", d.Driver))
	}
}

// DSN assembles the connection string handed to the storage layer.
//
// It is built through net/url rather than by formatting a string, so a password
// containing "@", "/" or ":" is percent-encoded instead of silently producing a
// DSN that points somewhere else.
func (d Database) DSN() string {
	if d.Driver == DriverMemory {
		return ":memory:"
	}

	dsn := url.URL{
		Scheme: string(d.Driver),
		User:   url.UserPassword(d.User, d.Password),
		Host:   net.JoinHostPort(d.Host, d.Port),
		Path:   "/" + d.Name,
	}

	return dsn.String()
}

// Redacted is the DSN with the password replaced, for logs and error messages.
//
// Nothing should ever print DSN itself: a connection string in a log line is a
// password in a log aggregator, read by more people than the database ever was.
func (d Database) Redacted() string {
	if d.Driver == DriverMemory {
		return ":memory:"
	}

	dsn := url.URL{
		Scheme: string(d.Driver),
		User:   url.User(d.User),
		Host:   net.JoinHostPort(d.Host, d.Port),
		Path:   "/" + d.Name,
	}

	return dsn.String()
}

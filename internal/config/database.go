package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
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
}

// Secrets are the credential halves of a connection string, resolved at run
// time and never read from the configuration file.
type Secrets struct {
	User     string
	Password string
	Name     string
}

// Validate implements the section contract, and canonicalises the driver name:
// the deployment file spells it "Postgres", the constants are lowercase.
//
// The pointer receiver is what lets it normalise in place; the sections that
// only inspect take a value receiver.
func (d *Database) Validate() error {
	d.Driver = Driver(strings.ToLower(strings.TrimSpace(string(d.Driver))))

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

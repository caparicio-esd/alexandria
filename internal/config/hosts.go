package config

import (
	"errors"
	"fmt"
	"net"
)

// ErrNoSuchHost reports that a transport was asked for that this deployment
// does not expose.
var ErrNoSuchHost = errors.New("host not configured")

// HostType is a transport an endpoint matrix can carry.
type HostType string

const (
	// HostHTTP is the web surface every node exposes.
	HostHTTP HostType = "http"
	// HostGRPC is the optional low-latency internal transport.
	HostGRPC HostType = "grpc"
	// HostGraphQL is the optional query interface.
	HostGraphQL HostType = "graphql"
)

// Hosts is a transport matrix: the HTTP endpoint is mandatory, the rest are
// present only where a deployment enables them.
type Hosts struct {
	HTTP    Endpoint  `mapstructure:"http"`
	GRPC    *Endpoint `mapstructure:"grpc,omitempty"`
	GraphQL *Endpoint `mapstructure:"graphql,omitempty"`
}

// Endpoint returns the endpoint for a transport, or ErrNoSuchHost when this
// deployment does not expose it.
//
// It reports an error rather than panicking: a caller asking for gRPC on an
// HTTP-only node is a configuration mismatch, and the operator deserves a
// message instead of a stack trace.
func (h Hosts) Endpoint(transport HostType) (Endpoint, error) {
	switch transport {
	case HostHTTP:
		return h.HTTP, nil
	case HostGRPC:
		if h.GRPC == nil {
			return Endpoint{}, fmt.Errorf("%s: %w", transport, ErrNoSuchHost)
		}

		return *h.GRPC, nil
	case HostGraphQL:
		if h.GraphQL == nil {
			return Endpoint{}, fmt.Errorf("%s: %w", transport, ErrNoSuchHost)
		}

		return *h.GraphQL, nil
	default:
		return Endpoint{}, fmt.Errorf("%s: %w", transport, ErrNoSuchHost)
	}
}

// Validate implements the section contract. The prefix names the matrix, since
// the same type is mounted under more than one key.
func (h Hosts) Validate(prefix string) error {
	errs := []error{h.HTTP.Validate(prefix + ".http")}

	if h.GRPC != nil {
		errs = append(errs, h.GRPC.Validate(prefix+".grpc"))
	}

	if h.GraphQL != nil {
		errs = append(errs, h.GraphQL.Validate(prefix+".graphql"))
	}

	return errors.Join(errs...)
}

// Endpoint is one reachable address, as seen from outside the cluster and from
// inside it.
//
// The optional fields are plain strings rather than pointers: an absent port
// and an empty port mean the same thing here, so the zero value carries the
// distinction without making every caller dereference.
type Endpoint struct {
	// Protocol is the scheme, "http" or "https".
	Protocol string `mapstructure:"protocol"`
	// Host is the domain name or address, with no scheme and no port.
	Host string `mapstructure:"url"`
	// Port is the externally published port. Empty means the scheme default.
	Port string `mapstructure:"port,omitempty"`
	// InternalPort is the port the container actually listens on, when a proxy
	// or an orchestrator remaps it. Empty means it matches Port.
	InternalPort string `mapstructure:"internal_port,omitempty"`
}

// Validate implements the section contract.
func (e Endpoint) Validate(prefix string) error {
	var errs []error

	if e.Protocol == "" {
		errs = append(errs, invalid(prefix+".protocol", "must be set, e.g. \"https\""))
	}

	if e.Host == "" {
		errs = append(errs, invalid(prefix+".url", "must be set"))
	}

	return errors.Join(errs...)
}

// URL is the address as the outside world reaches it. The port is omitted when
// it is not published, so a proxied deployment yields "https://example.org"
// rather than "https://example.org:443".
func (e Endpoint) URL() string {
	return e.Protocol + "://" + e.Authority()
}

// InternalURL is the address as the cluster reaches it, always with an explicit
// port: inside the mesh there is no proxy to supply the default.
func (e Endpoint) InternalURL() string {
	return e.Protocol + "://" + net.JoinHostPort(e.Host, e.PrivatePort())
}

// Authority is the host and, when published, the port — no scheme.
//
// net.JoinHostPort rather than a format string, so an IPv6 literal comes back
// bracketed and still parses.
func (e Endpoint) Authority() string {
	if e.Port == "" {
		return e.Host
	}

	return net.JoinHostPort(e.Host, e.Port)
}

// PublicPort is the published port, defaulting to the standard TLS port when
// none is set.
func (e Endpoint) PublicPort() string {
	if e.Port == "" {
		return "443"
	}

	return e.Port
}

// PrivatePort is the port the process listens on, falling back to the published
// one when the deployment does no remapping.
func (e Endpoint) PrivatePort() string {
	if e.InternalPort == "" {
		return e.PublicPort()
	}

	return e.InternalPort
}

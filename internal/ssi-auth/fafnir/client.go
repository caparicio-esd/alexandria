// Package fafnir is the driven adapter that backs the wallet ports with a
// remote Fafnir wallet instance, reached over HTTP.
//
// Nothing in here is imported by the domain: the wallet package declares the
// ports, and this package happens to satisfy them.
package fafnir

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"resty.dev/v3"
)

const defaultTimeout = 10 * time.Second

var _ wallet.Wallet = (*Adapter)(nil)

// Adapter talks to a Fafnir wallet over its HTTP API.
//
// The type is named Adapter rather than FafnirAdapter because the package
// qualifier already carries the name: callers read fafnir.Adapter.
type Adapter struct {
	http *resty.Client
}

// New builds an adapter pointed at the given Fafnir base URL, for example
// "http://localhost:7002". The URL is validated here so a typo fails at
// startup instead of on the first request.
func New(baseURL string) (*Adapter, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("fafnir: parsing base url %q: %w", baseURL, err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("fafnir: base url %q must be absolute", baseURL)
	}

	client := resty.New().
		SetBaseURL(strings.TrimSuffix(baseURL, "/")).
		SetTimeout(defaultTimeout).
		SetHeader("Accept", "application/json")

	return &Adapter{http: client}, nil
}

// Close releases the transport held by the underlying client. Call it once, when
// the process shuts down, not per request.
func (a *Adapter) Close() error {
	return a.http.Close()
}

// Link refreshes the wallet identity from whatever the remote considers its
// default DID. It satisfies the wallet.Wallet port.
func (a *Adapter) Link(ctx context.Context) (wallet.Did, error) {
	const path = "/dids/default"

	var out didResp

	res, err := a.http.R().
		SetContext(ctx).
		SetResult(&out).
		Get(path)
	if err != nil {
		return wallet.Did{}, fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.IsStatusFailure() {
		return wallet.Did{}, statusError(res.StatusCode(), path, res.Bytes())
	}

	if out.Did == "" {
		return wallet.Did{}, fmt.Errorf("fafnir: %s returned an empty did: %w", path, wallet.ErrNotFound)
	}

	return out.ToDomain()
}

// statusError turns a non-2xx response into a domain error, so callers can use
// errors.Is against the wallet sentinels without knowing HTTP exists.
func statusError(status int, path string, body []byte) error {
	var sentinel error

	switch status {
	case http.StatusNotFound:
		sentinel = wallet.ErrNotFound
	case http.StatusConflict:
		sentinel = wallet.ErrConflict
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		sentinel = wallet.ErrInvalidInput
	default:
		sentinel = errors.New("unexpected status")
	}

	return fmt.Errorf("fafnir: %s returned %d: %s: %w", path, status, body, sentinel)
}

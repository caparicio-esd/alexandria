// Package fafnir is the driven adapter that backs the wallet ports with a
// remote Fafnir wallet instance, reached over HTTP.
package fafnir

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"resty.dev/v3"
)

const defaultTimeout = 10 * time.Second

var _ wallet.Wallet = (*Adapter)(nil)

// Adapter talks to a Fafnir wallet over its HTTP API.
type Adapter struct {
	http   *resty.Client
	logger *slog.Logger
}

// New builds an adapter against the Fafnir instance at baseURL, which must be
// absolute: a relative one would send every call to whatever host the process
// happens to resolve, and fail late rather than here. A nil logger falls back to
// the default one.
func New(baseURL string, logger *slog.Logger) (*Adapter, error) {
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

	if logger == nil {
		logger = slog.Default()
	}

	return &Adapter{http: client, logger: logger}, nil
}

// Close releases the transport held by the underlying client
func (a *Adapter) Close() error {
	return a.http.Close()
}

// Link refreshes the wallet identity from whatever the remote considers its
// default DID. It satisfies the wallet.Wallet port.
func (a *Adapter) Link(ctx context.Context) (wallet.Did, error) {
	const path = "/dids/default"

	var out didResp

	// call
	started := time.Now()
	res, err := a.http.R().
		SetContext(ctx).
		SetResult(&out).
		Get(path)
	if err != nil {
		a.logger.DebugContext(ctx, "wallet call failed",
			"method", http.MethodGet, "path", path,
			"duration_ms", time.Since(started).Milliseconds(), "err", err)

		return wallet.Did{}, fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	a.logger.DebugContext(ctx, "wallet call",
		"method", http.MethodGet, "path", path,
		"status", res.StatusCode(), "duration_ms", time.Since(started).Milliseconds())

	// validate
	if res.IsStatusFailure() {
		return wallet.Did{}, statusError(res.StatusCode(), path, res.Bytes())
	}
	if out.Did == "" {
		return wallet.Did{}, fmt.Errorf("fafnir: %s returned an empty did: %w", path, common.ErrNotFound)
	}

	// send back to domain
	return out.ToDomain()
}

// RegisterKey imports raw PEM key material into the wallet
func (a *Adapter) RegisterKey(ctx context.Context, keyPlan *wallet.KeyPlan) error {
	const path = "/keys/new"

	// validate input
	if keyPlan == nil {
		return fmt.Errorf("fafnir: %s needs a key plan: %w", path, common.ErrInvalidInput)
	}

	// call
	started := time.Now()
	res, err := a.http.R().
		SetContext(ctx).
		SetBody(newKeyReq(*keyPlan)).
		Post(path)
	if err != nil {
		a.logger.DebugContext(ctx, "wallet call failed",
			"method", http.MethodPost, "path", path,
			"duration_ms", time.Since(started).Milliseconds(), "err", err)

		return fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	a.logger.DebugContext(ctx, "wallet call",
		"method", http.MethodPost, "path", path,
		"status", res.StatusCode(), "duration_ms", time.Since(started).Milliseconds())

	// validate
	if res.IsStatusFailure() {
		return statusError(res.StatusCode(), path, res.Bytes())
	}

	//
	return nil
}

// GetAllKeys lists every key the wallet holds. It satisfies the wallet.Wallet
// port.
func (a *Adapter) GetAllKeys(ctx context.Context) ([]wallet.Key, error) {
	const path = "/keys/all"

	var out []keyResp

	// call
	started := time.Now()
	res, err := a.http.R().
		SetContext(ctx).
		SetResult(&out).
		Get(path)
	if err != nil {
		a.logger.DebugContext(ctx, "wallet call failed",
			"method", http.MethodGet, "path", path,
			"duration_ms", time.Since(started).Milliseconds(), "err", err)

		return nil, fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	a.logger.DebugContext(ctx, "wallet call",
		"method", http.MethodGet, "path", path,
		"status", res.StatusCode(), "duration_ms", time.Since(started).Milliseconds())

	// validate
	if res.IsStatusFailure() {
		return nil, statusError(res.StatusCode(), path, res.Bytes())
	}

	// send back to domain
	keys := make([]wallet.Key, 0, len(out))
	for _, k := range out {
		key, err := k.ToDomain()
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (a *Adapter) DeleteKey(ctx context.Context, keyId string) error {
	path := fmt.Sprintf("/keys/%s", keyId)

	// call
	started := time.Now()
	res, err := a.http.R().
		SetContext(ctx).
		Delete(path)
	if err != nil {
		a.logger.DebugContext(ctx, "wallet call failed",
			"method", http.MethodDelete, "path", path,
			"duration_ms", time.Since(started).Milliseconds(), "err", err)

		return fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	a.logger.DebugContext(ctx, "wallet call",
		"method", http.MethodDelete, "path", path,
		"status", res.StatusCode(), "duration_ms", time.Since(started).Milliseconds())

	// validate
	if res.IsStatusFailure() {
		return statusError(res.StatusCode(), path, res.Bytes())
	}

	return nil
}

// RegisterDid asks the wallet to mint a DID from the given builder and bind the
// referenced keys into it, returning the identifier it minted.
func (a *Adapter) RegisterDid(
	ctx context.Context,
	didPlan *wallet.DidPlan,
) error {
	const path = "/dids/new"

	// validate input
	if didPlan == nil {
		return fmt.Errorf("fafnir: %s needs a did plan: %w", path, common.ErrInvalidInput)
	}
	didReq, err := newDidReq(*didPlan)
	if err != nil {
		return fmt.Errorf("fafnir: %s needs a did correct plan: %w", path, err)
	}

	// call
	started := time.Now()
	res, err := a.http.R().
		SetContext(ctx).
		SetBody(&didReq).
		Post(path)
	if err != nil {
		a.logger.DebugContext(ctx, "wallet call failed",
			"method", http.MethodPost, "path", path,
			"duration_ms", time.Since(started).Milliseconds(), "err", err)

		return fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	a.logger.DebugContext(ctx, "wallet call",
		"method", http.MethodPost, "path", path,
		"status", res.StatusCode(), "duration_ms", time.Since(started).Milliseconds())

	// validate
	if res.IsStatusFailure() {
		return statusError(res.StatusCode(), path, res.Bytes())
	}

	//
	return nil
}

func (a *Adapter) DeleteDid(ctx context.Context, keyId string) error {
	path := fmt.Sprintf("/dids/%s", keyId)

	// call
	started := time.Now()
	res, err := a.http.R().
		SetContext(ctx).
		Delete(path)
	if err != nil {
		a.logger.DebugContext(ctx, "wallet call failed",
			"method", http.MethodDelete, "path", path,
			"duration_ms", time.Since(started).Milliseconds(), "err", err)

		return fmt.Errorf("fafnir: calling %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	a.logger.DebugContext(ctx, "wallet call",
		"method", http.MethodDelete, "path", path,
		"status", res.StatusCode(), "duration_ms", time.Since(started).Milliseconds())

	// validate
	if res.IsStatusFailure() {
		return statusError(res.StatusCode(), path, res.Bytes())
	}

	return nil
}

// ===== HELPERS ===============================================================

// statusError turns a non-2xx response into a domain error, so callers can use
// errors.Is against the wallet sentinels without knowing HTTP exists.
func statusError(status int, path string, body []byte) error {
	var sentinel error

	switch status {
	case http.StatusNotFound:
		sentinel = common.ErrNotFound
	case http.StatusConflict:
		sentinel = common.ErrConflict
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		sentinel = common.ErrInvalidInput
	default:
		sentinel = errors.New("unexpected status")
	}

	return fmt.Errorf("fafnir: %s returned %d: %s: %w", path, status, body, sentinel)
}

// The wallet handshake: how the node acquires the identity everything else
// depends on, and what it does while it has not.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
)

// Wallet handshake backoff. The first pause is short because the common case is
// a wallet seconds away from ready; the cap keeps a long outage from stretching
// the gap out to something useless.
const (
	linkFirstBackoff = 500 * time.Millisecond
	linkMaxBackoff   = 10 * time.Second
)

// linkWallet spends a bounded budget trying to link, then hands the job to a
// background goroutine.
//
// Blocking briefly catches the common case, where the node and its wallet start
// together and the wallet is seconds behind. Past the budget, refusing to start
// would only produce a restart loop: the node comes up, reports itself not
// ready, and keeps trying — which is what an orchestrator knows how to act on.
func linkWallet(
	ctx context.Context,
	background *sync.WaitGroup,
	holder *wallet.Service,
	budget time.Duration,
	out *report,
	logger *slog.Logger,
) {
	notify := func(attempt int, backoff time.Duration, err error) {
		if reportErr := out.waiting(attempt, backoff.String(), err.Error()); reportErr != nil {
			logger.WarnContext(ctx, "wallet not ready", "attempt", attempt, "err", err)
		}
	}

	budgeted, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	identity, err := retryLink(budgeted, holder, notify)
	if err == nil {
		logger.InfoContext(ctx, "wallet linked", "did", identity.ID, "alias", identity.Alias)

		if reportErr := out.linked(identity); reportErr != nil {
			logger.WarnContext(ctx, "writing the startup report", "err", reportErr)
		}

		return
	}

	logger.WarnContext(ctx, "wallet not linked within the startup budget; retrying in the background",
		"budget", budget.String(), "err", err)

	background.Add(1)

	go func() {
		defer background.Done()

		identity, err := retryLink(ctx, holder, nil)
		if err != nil {
			// The only way out of the loop besides success is the process
			// shutting down, so this is expected on the way out.
			logger.InfoContext(ctx, "wallet link abandoned", "err", err)

			return
		}

		logger.InfoContext(ctx, "wallet linked", "did", identity.ID, "alias", identity.Alias)
	}()
}

// retryLink attempts the handshake until it succeeds or the context ends,
// pausing on a capped exponential backoff between attempts.
func retryLink(
	ctx context.Context,
	holder *wallet.Service,
	notify func(attempt int, backoff time.Duration, err error),
) (wallet.Did, error) {
	backoff := linkFirstBackoff

	for attempt := 1; ; attempt++ {
		identity, err := holder.Link(ctx)
		if err == nil {
			return identity, nil
		}

		// The budget and the shutdown signal both land here as a cancelled
		// context, and neither is worth another attempt.
		if ctx.Err() != nil {
			return wallet.Did{}, fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		}

		if notify != nil {
			notify(attempt, backoff, err)
		}

		select {
		case <-ctx.Done():
			return wallet.Did{}, fmt.Errorf("linking wallet after %d attempts: %w", attempt, err)
		case <-time.After(backoff):
		}

		// No jitter: there is one client here, so there is no herd to spread.
		backoff = min(backoff*2, linkMaxBackoff)
	}
}

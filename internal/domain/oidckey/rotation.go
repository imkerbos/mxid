package oidckey

import (
	"context"
	"time"
)

// RunRotation drives automatic keyset rotation. It ensures an active key exists,
// then on each tick rotates the active key once it is older than `every` and
// retires rotating keys past their expiry. Blocks until ctx is cancelled — run
// it in a goroutine. A zero/negative `every` disables rotation (ensure-only).
//
// onErr (optional) is called with any background error so the caller can log it.
func (s *Service) RunRotation(ctx context.Context, every time.Duration, onErr func(error)) {
	report := func(err error) {
		if err != nil && onErr != nil {
			onErr(err)
		}
	}

	if _, err := s.EnsureActive(ctx); err != nil {
		report(err)
	}
	if every <= 0 {
		return // rotation disabled; key minted, nothing more to do
	}

	// Check a few times within each rotation window so a long uptime still
	// rotates near the boundary rather than a full window late.
	interval := max(every/12, time.Hour)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.MaybeRotate(ctx, every); err != nil {
				report(err)
			}
			if err := s.RetireExpired(ctx); err != nil {
				report(err)
			}
		}
	}
}

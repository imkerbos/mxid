package access

import (
	"context"
	"time"

	"github.com/imkerbos/mxid/pkg/tenantscope"
	"go.uber.org/zap"
)

// StartSweeper runs sweepOnce every interval until ctx is cancelled. The
// resolver-level expires_at filter is the real enforcement; this loop is
// cleanup + audit + cache eviction for grants that crossed their TTL.
func StartSweeper(ctx context.Context, svc *Service, repo Repository, interval time.Duration, logger *zap.Logger) {
	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepOnce(ctx, svc, repo, logger)
			}
		}
	}()
}

// sweepOnce queries for all approved grants whose expires_at has passed and
// calls svc.Expire on each one. Errors from individual expirations are logged
// and skipped so one bad grant cannot block the rest. Returns the count of
// successfully expired grants.
func sweepOnce(ctx context.Context, svc *Service, repo Repository, logger *zap.Logger) int {
	// Cross-tenant background job: list due grants across ALL tenants under a
	// system scope (the ONLY sanctioned way for a context-less goroutine to
	// touch tenant-scoped tables — otherwise the tenantscope plugin fail-closes).
	sysCtx := tenantscope.WithSystem(ctx)
	due, err := repo.ListDueGrants(sysCtx)
	if err != nil {
		logger.Error("sweep: list due grants failed", zap.Error(err))
		return 0
	}
	n := 0
	for _, req := range due {
		// Expire each grant pinned to its own tenant so writes + audit land on
		// the correct tenant.
		reqCtx := tenantscope.WithTenant(ctx, req.TenantID)
		if err := svc.Expire(reqCtx, req); err != nil {
			logger.Error("sweep: expire failed",
				zap.Int64("request_id", req.ID),
				zap.Int64("tenant_id", req.TenantID),
				zap.Error(err),
			)
			continue
		}
		n++
	}
	if n > 0 {
		logger.Info("sweep: expired grants", zap.Int("count", n))
	}
	return n
}

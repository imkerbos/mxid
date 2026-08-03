package group

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// SubscribeEvents wires the group service to org-membership domain events so a
// dynamic group whose rule keys on org membership (org_id eq/in/in_subtree)
// recomputes automatically when the org roster changes — no manual re-sync.
//
// Safe to call on a nil event bus (Subscribe is a no-op there): unit embeddings
// that build a bus-less Service simply skip the wiring.
func (s *Service) SubscribeEvents() {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Subscribe(event.OrgMemberAdded, s.handleOrgMemberChange)
	s.eventBus.Subscribe(event.OrgMemberRemoved, s.handleOrgMemberChange)
	// (OrgMemberMoved is never published — Added/Removed cover membership; dropped.)
	// An org re-parent (ltree path change) shifts subtree membership without any
	// per-user event, so in_subtree rules would otherwise go stale. Same handler
	// — it recomputes every dynamic group in the org's tenant.
	s.eventBus.Subscribe(event.OrgMoved, s.handleOrgMemberChange)
	// A user attribute change (status / department / job_title …) can flip a
	// dynamic group whose rule keys on it. UserUpdated now carries tenant_id, so
	// the same tenant-wide recompute applies.
	s.eventBus.Subscribe(event.UserUpdated, s.handleOrgMemberChange)
}

// handleOrgMemberChange recomputes every dynamic group in the affected tenant.
// Runs asynchronously on the event bus, so it must not depend on the originating
// request's context (which may already be cancelled) — it rebuilds a fresh
// tenant-scoped context from the event's tenant_id.
func (s *Service) handleOrgMemberChange(_ context.Context, evt event.Event) {
	payload, ok := evt.Payload.(map[string]any)
	if !ok {
		return
	}
	tenantID := toInt64Any(payload["tenant_id"])
	if tenantID == 0 {
		return
	}
	s.scheduleResync(tenantID)
}

// resyncDebounce is how long a pending recompute waits for more events before
// running. Dynamic-group membership is eventually consistent by design — the
// rules are re-evaluated, not incrementally patched — so coalescing costs a
// short delay and nothing else.
const resyncDebounce = 2 * time.Second

// scheduleResync coalesces recomputes per tenant.
//
// Each recompute walks every dynamic group in the tenant and full-scans
// mxid_user once per group. Firing one per event made a single admin action
// self-amplifying: BatchAction calls UpdateStatus per user, so disabling 200
// users emitted 200 UserUpdated events, each spawning a goroutine that ran G
// full scans — 200×G scans to converge on a result that one pass would have
// produced.
//
// A pending timer per tenant collapses that to one pass. Trailing edge rather
// than leading: the last event carries the final state, and running first would
// recompute against a half-applied batch and then have to run again anyway.
func (s *Service) scheduleResync(tenantID int64) {
	s.resyncMu.Lock()
	defer s.resyncMu.Unlock()
	if s.resyncTimers == nil {
		s.resyncTimers = make(map[int64]*time.Timer)
	}
	if t, ok := s.resyncTimers[tenantID]; ok {
		// Push the deadline out; a burst keeps resetting it and runs once at the
		// end. Reset on an already-fired timer is harmless here because the fired
		// callback removes its own entry under the same lock before running.
		t.Reset(resyncDebounce)
		return
	}
	s.resyncTimers[tenantID] = time.AfterFunc(resyncDebounce, func() {
		s.resyncMu.Lock()
		delete(s.resyncTimers, tenantID)
		s.resyncMu.Unlock()

		ctx := tenantscope.WithTenant(context.Background(), tenantID)
		s.ResyncTenantDynamicGroups(ctx, tenantID)
	})
}

// ResyncTenantDynamicGroups re-runs SyncRule for every dynamic group in the
// tenant. Errors are logged and skipped so one broken rule cannot stall the
// rest. ctx must already carry the tenant scope.
func (s *Service) ResyncTenantDynamicGroups(ctx context.Context, tenantID int64) {
	ids, err := s.repo.ListDynamicGroupIDs(ctx, tenantID)
	if err != nil {
		s.logger.Warn("resync dynamic groups: list failed",
			zap.Int64("tenant_id", tenantID), zap.Error(err))
		return
	}
	for _, gid := range ids {
		if _, err := s.SyncRule(ctx, gid); err != nil {
			s.logger.Warn("resync dynamic group failed",
				zap.Int64("tenant_id", tenantID), zap.Int64("group_id", gid), zap.Error(err))
		}
	}
}

// toInt64Any coerces an event-payload numeric (which may arrive as int64,
// float64, or int depending on the producer) to int64. Returns 0 on mismatch.
func toInt64Any(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

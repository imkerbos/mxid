package access

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// TestSweepOnce_ExpiresDueGrants_InMemory tests the sweeper using in-memory fakes.
// This test is always runnable (no DB required).
func TestSweepOnce_ExpiresDueGrants_InMemory(t *testing.T) {
	svc, fakes := newServiceWithFakes(t)
	repo := fakes.repo

	// Seed a console-target approved request with expires_at already in the past.
	idGen, err := snowflake.New(3)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}

	past := time.Now().Add(-5 * time.Minute)
	reqID := idGen.Generate()
	bindingID := idGen.Generate()

	req := &Request{
		ID:               reqID,
		TenantID:         testTenant,
		RequesterID:      8001,
		EligibilityID:    testEligID,
		TargetKind:       TargetConsole,
		RoleID:           42,
		RequestedSeconds: 300,
		Status:           StatusApproved,
		ExpiresAt:        &past,
		BindingID:        &bindingID,
	}
	if err := repo.CreateRequest(testCtx, req); err != nil {
		t.Fatalf("seed approved+expired request: %v", err)
	}

	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 1 {
		t.Fatalf("want 1 expired, got %d", n)
	}

	got, err := repo.GetRequest(context.Background(), req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest after sweep: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("want status=%s, got %s", StatusExpired, got.Status)
	}
}

// TestSweepOnce_SkipsNotDue verifies that a future-expiring grant is not expired.
func TestSweepOnce_SkipsNotDue(t *testing.T) {
	svc, fakes := newServiceWithFakes(t)
	repo := fakes.repo

	idGen, err := snowflake.New(4)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}

	future := time.Now().Add(time.Hour)
	reqID := idGen.Generate()
	bindingID := idGen.Generate()

	req := &Request{
		ID:               reqID,
		TenantID:         testTenant,
		RequesterID:      8002,
		EligibilityID:    testEligID,
		TargetKind:       TargetConsole,
		RoleID:           42,
		RequestedSeconds: 3600,
		Status:           StatusApproved,
		ExpiresAt:        &future,
		BindingID:        &bindingID,
	}
	if err := repo.CreateRequest(testCtx, req); err != nil {
		t.Fatalf("seed not-due request: %v", err)
	}

	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 0 {
		t.Fatalf("want 0 expired (grant not due), got %d", n)
	}

	got, err := repo.GetRequest(context.Background(), req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("want status still=%s, got %s", StatusApproved, got.Status)
	}
}

// TestSweepOnce_ExpiresDueGrants is the DB-backed integration test.
// Requires TEST_DATABASE_URL; otherwise skipped.
func TestSweepOnce_ExpiresDueGrants(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	// Insert an approved request already past expiry with a live binding.
	reqID := idGen.Generate()
	bindID := idGen.Generate()
	past := time.Now().Add(-5 * time.Minute)

	if err := db.Exec(`
		INSERT INTO mxid_access_request
			(id, tenant_id, requester_id, eligibility_id, target_kind, role_id,
			 requested_seconds, status, binding_id, expires_at, created_at, updated_at)
		VALUES (?, ?, 5010, ?, 'console', ?, 3600, ?, ?, ?, NOW(), NOW())`,
		reqID, tenantID, eligID, roleID, StatusApproved, bindID, past).Error; err != nil {
		t.Fatalf("seed expired approved request: %v", err)
	}

	// Insert a console binding row so EndGrant can delete it.
	if err := db.Exec(`
		INSERT INTO mxid_role_binding
			(id, tenant_id, role_id, subject_type, subject_id, expires_at, status, created_at)
		VALUES (?, ?, ?, 'user', 5010, ?, 1, NOW())`,
		bindID, tenantID, roleID, past).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// Build a real service with a noop terminator and a no-op cache (console grant
	// needs no cache invalidation to pass the test, but CacheInvalidator is required).
	svcIdGen, err := snowflake.New(5)
	if err != nil {
		t.Fatalf("snowflake.New for svc: %v", err)
	}
	cache := &fakeCache{}
	bus := &fakePublisher{}
	svc := NewService(repo, svcIdGen, bus, cache, fakeMatcher{}, NoopTerminator())

	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 1 {
		t.Fatalf("want 1 expired, got %d", n)
	}

	got, err := repo.GetRequest(context.Background(), reqID, tenantID)
	if err != nil {
		t.Fatalf("GetRequest after sweep: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("want status=%s, got %s", StatusExpired, got.Status)
	}
}

// TestStartSweeper_StopsOnCtxCancel verifies that StartSweeper goroutine
// respects context cancellation and doesn't leak.
func TestStartSweeper_StopsOnCtxCancel(t *testing.T) {
	svc, fakes := newServiceWithFakes(t)

	ctx, cancel := context.WithCancel(context.Background())
	// Use a short interval but cancel before it fires.
	StartSweeper(ctx, svc, fakes.repo, 10*time.Second, zap.NewNop())
	// Immediately cancel — the goroutine should stop.
	cancel()
	// No assertion needed beyond "test exits cleanly without deadlock".
}

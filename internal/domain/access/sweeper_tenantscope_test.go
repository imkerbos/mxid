package access

// Regression test for commit 2aee337 ("fix(access): run JIT expiry sweeper
// under system tenant scope"). sweepOnce calls repo.ListDueGrants(ctx) with
// the bare context StartSweeper hands it (no tenant in scope, since it is a
// context-less background goroutine). mxid_access_request is a
// tenantscope.Tenanted model, so the tenantscope GORM plugin fail-closes
// (returns ErrNoTenantScope) on that query unless sweepOnce first escapes via
// tenantscope.WithSystem(ctx). Every other test in this package either uses
// an in-memory fake repo (no GORM at all) or a real Postgres *gorm.DB that
// never had the plugin installed — so none of them actually exercised the
// fail-closed behavior the fix depends on. This test installs the real
// production plugin (the exact call internal/bootstrap/database.go makes)
// on the test *gorm.DB so a revert of the WithSystem escape makes this test
// fail, not just the ones using fakes.
//
// Requires TEST_DATABASE_URL; otherwise skipped (see repository_test.go).

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// setupAccessRepoWithTenantScope is setupAccessRepo plus the tenantscope
// plugin installed on the underlying *gorm.DB — mirroring exactly what
// internal/bootstrap/database.go does for the production connection
// (db.Use(tenantscope.NewPlugin())). Isolation follows the same
// transaction-rollback pattern as setupAccessRepo: Begin() before install
// would be equally valid since a *gorm.DB clone/transaction shares the parent
// db's registered callbacks, but installing before Begin matches production
// (the plugin is installed once on the long-lived db, and every request/tx
// derives from it).
func setupAccessRepoWithTenantScope(t *testing.T) (Repository, *gorm.DB, *snowflake.Generator, int64) {
	t.Helper()
	db := openAccessTestDB(t)
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("install tenantscope plugin: %v", err)
	}

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin tx: %v", tx.Error)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	idGen, err := snowflake.New(9)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}

	const tenantID = int64(1) // default system tenant, same as setupAccessRepo
	return NewRepository(tx, idGen), tx, idGen, tenantID
}

// TestSweepOnce_ExpiresDueGrant_WithTenantScopePlugin is the load-bearing
// regression test: it seeds one due (approved + past expires_at) console
// grant, calls sweepOnce with a bare context.Background() — exactly like
// StartSweeper does in production — against a repo whose *gorm.DB has the
// real tenantscope plugin installed, and asserts the grant is actually
// expired. If sweepOnce's tenantscope.WithSystem(ctx) escape around
// ListDueGrants is ever reverted, ListDueGrants fails closed with
// tenantscope.ErrNoTenantScope, sweepOnce logs the error and returns 0, and
// this test fails.
func TestSweepOnce_ExpiresDueGrant_WithTenantScopePlugin(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepoWithTenantScope(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	reqID := idGen.Generate()
	bindID := idGen.Generate()
	past := time.Now().Add(-time.Hour)

	// Seed via raw SQL (bypasses the GORM model path / plugin entirely, same
	// as the other DB-backed tests in this package) so the seed itself can't
	// be affected by the plugin being installed.
	if err := db.Exec(`
		INSERT INTO mxid_access_request
			(id, tenant_id, requester_id, eligibility_id, target_kind, role_id,
			 requested_seconds, status, binding_id, expires_at, created_at, updated_at)
		VALUES (?, ?, 9010, ?, 'console', ?, 3600, ?, ?, ?, NOW(), NOW())`,
		reqID, tenantID, eligID, roleID, StatusApproved, bindID, past).Error; err != nil {
		t.Fatalf("seed expired approved request: %v", err)
	}
	// mxid_role_binding has no tenant_id column of its own — tenancy is
	// derived via role_id -> mxid_role.tenant_id (see repository.go's
	// insertBindingTx column comment, verified against migration 000045).
	if err := db.Exec(`
		INSERT INTO mxid_role_binding
			(id, role_id, subject_type, subject_id, expires_at, status, created_at)
		VALUES (?, ?, 'user', 9010, ?, 1, NOW())`,
		bindID, roleID, past).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	svcIdGen, err := snowflake.New(10)
	if err != nil {
		t.Fatalf("snowflake.New for svc: %v", err)
	}
	cache := &fakeCache{}
	bus := &fakePublisher{}
	svc := NewService(repo, svcIdGen, bus, cache, fakeMatcher{}, NoopTerminator())

	// The exact call StartSweeper makes on every tick: a bare, unscoped
	// context. No tenantscope.WithSystem/WithTenant here — that escape must
	// come from inside sweepOnce itself.
	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 1 {
		t.Fatalf("want 1 expired grant, got %d (tenantscope plugin likely fail-closed ListDueGrants — see sweeper.go sweepOnce's tenantscope.WithSystem escape)", n)
	}

	// Assert directly via raw SQL (bypasses the plugin, same rationale as the
	// seed) so the assertion itself never depends on scope plumbing.
	var status string
	if err := db.Raw(`SELECT status FROM mxid_access_request WHERE id = ?`, reqID).Scan(&status).Error; err != nil {
		t.Fatalf("query request status: %v", err)
	}
	if status != StatusExpired {
		t.Fatalf("want status=%s, got %s", StatusExpired, status)
	}

	var bindingCount int64
	if err := db.Raw(`SELECT count(*) FROM mxid_role_binding WHERE id = ?`, bindID).Scan(&bindingCount).Error; err != nil {
		t.Fatalf("query binding count: %v", err)
	}
	if bindingCount != 0 {
		t.Fatalf("binding row should have been deleted by EndGrant, found %d", bindingCount)
	}
}

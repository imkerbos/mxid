package access

import (
	"fmt"
	"testing"

	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// batchNames resolves display names through a .Table() query scanning into an
// anonymous struct. That shape carries no model type, so the tenantscope plugin
// has nothing to key off and leaves the statement bare — the predicate has to be
// written by hand, and this proves it is.
//
// The ids reaching batchNames come from rows already loaded under the caller's
// tenant, so this is the second layer, not the first.
//
// Postgres-backed like its neighbours in this package: skips without
// TEST_DATABASE_URL.
func TestBatchNames_DoesNotResolveAnotherTenantsRow(t *testing.T) {
	repoIface, tx, _, tenantID := setupAccessRepo(t)
	r, ok := repoIface.(*repo)
	if !ok {
		t.Fatalf("expected *repo, got %T", repoIface)
	}

	mine := seedConsoleRole(t, tx, tenantID)

	// mxid_role.tenant_id carries an FK, so the foreign tenant has to exist.
	// Everything here rides the rollback-on-cleanup transaction.
	otherTenant := accessNextID()
	if err := tx.Exec(`
		INSERT INTO mxid_tenant (id, name, code, created_at, updated_at)
		VALUES (?, ?, ?, NOW(), NOW())`,
		otherTenant, fmt.Sprintf("jit-other-%d", otherTenant), fmt.Sprintf("jit-other-%d", otherTenant),
	).Error; err != nil {
		t.Fatalf("seed foreign tenant: %v", err)
	}

	theirs := accessNextID()
	code := fmt.Sprintf("jit-foreign-role-%d", theirs)
	if err := tx.Exec(`
		INSERT INTO mxid_role (id, tenant_id, name, code, type, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, NOW(), NOW())`,
		theirs, otherTenant, code, code).Error; err != nil {
		t.Fatalf("seed foreign role: %v", err)
	}

	ctx := tenantscope.WithTenant(t.Context(), tenantID)
	got := r.batchNames(ctx, "mxid_role", []int64{mine, theirs}, true)

	if _, leaked := got[theirs]; leaked {
		t.Fatalf("resolved the name of a role belonging to tenant %d while scoped to tenant %d; "+
			"batchNames turns any id into a name, which makes it a cross-tenant oracle", otherTenant, tenantID)
	}
	if got[mine] == "" {
		t.Fatalf("the caller's own row must still resolve; got %v", got)
	}
}

// TestBatchNames_SharedRowsStillResolve pins the `OR tenant_id IS NULL` half of
// the predicate. mxid_app is nullable there for apps shared across tenants, and
// a plain equality check would blank their names.
func TestBatchNames_SharedRowsStillResolve(t *testing.T) {
	repoIface, tx, _, tenantID := setupAccessRepo(t)
	r, ok := repoIface.(*repo)
	if !ok {
		t.Fatalf("expected *repo, got %T", repoIface)
	}

	shared := accessNextID()
	code := fmt.Sprintf("jit-shared-app-%d", shared)
	if err := tx.Exec(`
		INSERT INTO mxid_app (id, tenant_id, name, code, protocol, client_type, client_secret, status,
		                      protocol_config, redirect_uris, created_at, updated_at)
		VALUES (?, NULL, ?, ?, 'oidc', 'spa', NULL, 1, '{}'::jsonb, '[]'::jsonb, NOW(), NOW())`,
		shared, code, code).Error; err != nil {
		t.Fatalf("seed shared app: %v", err)
	}

	ctx := tenantscope.WithTenant(t.Context(), tenantID)
	got := r.batchNames(ctx, "mxid_app", []int64{shared}, true)

	if got[shared] == "" {
		t.Fatalf("an app shared across tenants (tenant_id IS NULL) lost its name under the tenant "+
			"predicate; got %v", got)
	}
}

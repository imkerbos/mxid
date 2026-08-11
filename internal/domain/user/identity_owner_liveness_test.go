package user

// A binding must never end up live on an account nobody can load. That shape —
// live binding, dead owner — is what Service.Delete's identity sweep exists to
// eliminate, and it is the shape that produced the 2026-08-10 lockout.
//
// Two paths could still create it, because both check the BINDING and never the
// OWNER:
//
//   - BindExternalIdentity validated only that in.UserID != 0. Session
//     revocation on delete is best-effort and detached (app/run.go publishes
//     revokeUserSessions through safego.Go, errors only logged), and nothing on
//     the request path re-reads deleted_at, so a soft-deleted user whose
//     revocation did not land still holds a working cookie. EE's finishBind
//     takes bindUserID from Redis state and the tenant from the IdP row, and
//     cross-checks neither against the user.
//   - RestoreIdentity checked that the external id was free and that the row
//     belonged to the given user, never that the user is still live. The
//     console's "show deleted" filter puts a deleted user's id one click away.
//
// These tests fail if either check is removed.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestBindRefusesWhenCallerIsSoftDeleted reproduces the surviving-cookie case:
// the account is soft-deleted, its session was never revoked, and the OAuth
// round-trip completes. Without the owner check the bind SUCCEEDS and writes a
// live binding onto a deleted user.
func TestBindRefusesWhenCallerIsSoftDeleted(t *testing.T) {
	svc, repo, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed caller: %v", err)
	}
	// repo.Delete is the soft delete; the caller's session is deliberately NOT
	// revoked here, which is exactly the state a dropped revocation leaves.
	if err := repo.Delete(ctx, 1); err != nil {
		t.Fatalf("soft delete caller: %v", err)
	}

	err := svc.BindExternalIdentity(ctx, bindInput(1))
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("a soft-deleted caller must not be able to bind, want ErrUserNotFound, got %v", err)
	}

	var rows []UserIdentity
	if err := db.Unscoped().Where("external_id = ?", "ext-1").Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("no binding may be written for a deleted caller, got %+v", rows)
	}
}

// TestBindRefusesOnTenantMismatch pins the other half of the check. The
// identity's tenant comes from the IdP row and the user id from the session;
// EE cross-checks neither, so only this refusal keeps a binding from landing in
// a tenant its owner is not in.
func TestBindRefusesOnTenantMismatch(t *testing.T) {
	svc, _, db := newDeleteCascadeTestService(t)
	now := time.Now().UTC()

	// The caller lives in tenant 2; the bind claims tenant 1.
	if err := db.Create(&User{ID: 1, TenantID: 2, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed caller: %v", err)
	}

	in := bindInput(1) // TenantID: 1
	err := svc.BindExternalIdentity(context.Background(), in)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("a cross-tenant bind must be refused, want ErrUserNotFound, got %v", err)
	}

	var rows []UserIdentity
	if err := db.Unscoped().Where("external_id = ?", "ext-1").Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("no binding may be written across tenants, got %+v", rows)
	}
}

// TestRestoreIdentityRefusesWhenOwnerIsDeleted covers the console path. The
// refusal must name the fix, because unlike a login refusal the administrator
// can act on it: restore the account, then the binding.
func TestRestoreIdentityRefusesWhenOwnerIsDeleted(t *testing.T) {
	svc, repo, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	// Service.Delete sweeps the binding and soft-deletes the user — the exact
	// state the console's "show deleted" list then offers for restore.
	if err := svc.Delete(ctx, 1); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	err := svc.RestoreIdentity(ctx, 1, 10)
	if !errors.Is(err, ErrIdentityOwnerDeleted) {
		t.Fatalf("restoring a binding onto a deleted account must be refused, "+
			"want ErrIdentityOwnerDeleted, got %v", err)
	}
	if !strings.Contains(err.Error(), "restore the account") {
		t.Fatalf("the refusal must tell the administrator what to do first, got %q", err)
	}

	// And the binding must still be deleted — a refusal that half-applied
	// would be worse than the bug.
	var row UserIdentity
	if err := db.Unscoped().Where("id = ?", 10).First(&row).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if row.DeletedAt.Valid == false {
		t.Fatal("the binding must stay unbound after a refused restore")
	}
	// repo.Delete's soft delete is what the guard reads; assert it directly so a
	// future change to Service.Delete cannot make this test vacuous.
	if _, err := repo.GetByID(ctx, 1); err == nil {
		t.Fatal("the owner must be soft-deleted for this test to mean anything")
	}
}

// TestRestoreIdentityStillWorksForALiveOwner is the negative control: the guard
// above must not have made the ordinary console restore impossible.
func TestRestoreIdentityStillWorksForALiveOwner(t *testing.T) {
	svc, _, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := db.Where("user_id = ? AND id = ?", 1, 10).Delete(&UserIdentity{}).Error; err != nil {
		t.Fatalf("unbind: %v", err)
	}

	if err := svc.RestoreIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("restoring onto a live owner must still work, got %v", err)
	}
	var live []UserIdentity
	if err := db.Where("id = ?", 10).Find(&live).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("the binding must be live again, got %+v", live)
	}
}

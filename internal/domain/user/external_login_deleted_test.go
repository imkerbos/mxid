package user

// ResolveExternalLogin used to have exactly two outcomes when the live
// binding lookup missed: wrap GetByID's not-found into an opaque error with
// no fallthrough, or (once Task 9 started sweeping bindings on delete) fall
// through to AutoCreate and mint a replacement account behind the
// administrator's back. Neither distinguishes "the account was deleted" from
// "an administrator merely unbound this identity, but the account is still
// live" — Task 6 added a console restore button for exactly that second
// case. Telling that user their account was deleted would be false, and a
// false statement about a user's own account is the same class of defect as
// the incident that started this work. These tests pin the outcomes the
// corrected logic must produce, reusing the Service assembly Task 9 built in
// delete_cascade_service_test.go (newDeleteCascadeTestService) rather than
// duplicating it.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestResolveExternalLoginRefusesDeletedAccount pins the common case going
// forward: Task 9 sweeps a user's bindings before deleting the user, so a
// deleted user's binding is soft-deleted, not orphaned. AutoCreate is on —
// the point is that it must NOT kick in and mint a replacement account
// behind the administrator's back.
func TestResolveExternalLoginRefusesDeletedAccount(t *testing.T) {
	svc, _, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	// Delete the user the way the admin API does.
	if err := svc.Delete(ctx, 1); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	// AutoCreate is on — the point is that it must NOT kick in and mint a
	// replacement account behind the administrator's back.
	_, err := svc.ResolveExternalLogin(ctx, &ExternalLoginInput{
		TenantID: 1, ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		Username: "layne", AutoCreate: true,
	})
	if !errors.Is(err, ErrExternalUserDeleted) {
		t.Fatalf("want ErrExternalUserDeleted, got %v", err)
	}

	var count int64
	db.Model(&User{}).Where("username LIKE ?", "layne%").Count(&count)
	if count != 0 {
		t.Fatalf("a deleted account must not be silently replaced, %d live users appeared", count)
	}
}

// TestResolveExternalLoginRefusesOrphanBinding pins the pre-Task-9 data
// shape that actually caused the production incident: the binding itself is
// still live (never swept — this predates the sweep this branch adds), but
// the user row it points at is gone. GetByID misses and the old code wrapped
// that into a generic "get linked user" error with no useful message. It
// must now be named the same way as any other deleted-account login.
func TestResolveExternalLoginRefusesOrphanBinding(t *testing.T) {
	svc, _, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// No User row for id 99 at all — the binding points nowhere, exactly
	// the orphan shape from the incident (pre-sweep data).
	if err := db.Create(&UserIdentity{
		ID: 20, UserID: 99, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-orphan",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed orphan identity: %v", err)
	}

	_, err := svc.ResolveExternalLogin(ctx, &ExternalLoginInput{
		TenantID: 1, ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-orphan",
		Username: "orphan", AutoCreate: true,
	})
	if !errors.Is(err, ErrExternalUserDeleted) {
		t.Fatalf("want ErrExternalUserDeleted, got %v", err)
	}
}

// TestResolveExternalLoginUnbindOnlyIsNotLinkedNotDeleted is the controller
// ruling's central case. An administrator unbinds an identity while the
// account stays perfectly alive (Task 6's console restore button exists for
// exactly this). The user did nothing wrong and their account was never
// touched — telling them "your account was deleted" would be false. They
// must get ErrExternalUserNotLinked, the same "no account, contact an
// administrator" outcome as never having been bound at all, and AutoCreate
// must not fire either: an unbind is an administrator's intent exactly as a
// delete is.
func TestResolveExternalLoginUnbindOnlyIsNotLinkedNotDeleted(t *testing.T) {
	svc, repo, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 2, TenantID: 1, Username: "still-here", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 30, UserID: 2, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-unbound",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	// The admin unbinds via the console action — the user account is
	// completely untouched.
	if err := repo.DeleteIdentity(ctx, 2, 30); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	_, err := svc.ResolveExternalLogin(ctx, &ExternalLoginInput{
		TenantID: 1, ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-unbound",
		Username: "still-here", AutoCreate: true,
	})
	if !errors.Is(err, ErrExternalUserNotLinked) {
		t.Fatalf("want ErrExternalUserNotLinked (account is alive, only the binding was unbound), got %v", err)
	}
	if errors.Is(err, ErrExternalUserDeleted) {
		t.Fatal("a merely-unbound identity must never be told its account was deleted")
	}

	var count int64
	db.Model(&User{}).Where("username = ?", "still-here").Count(&count)
	if count != 1 {
		t.Fatalf("AutoCreate must not fire; the original account must remain exactly once, got %d", count)
	}
}

// TestResolveExternalLoginAutoCreatesWhenNeverBound guards the ordinary
// AutoCreate path against this task's new "was there ever a binding" check:
// an external id that has never been bound to anything — live or
// soft-deleted — must still provision a new account when AutoCreate is on.
func TestResolveExternalLoginAutoCreatesWhenNeverBound(t *testing.T) {
	svc, _, _ := newDeleteCascadeTestService(t)
	ctx := context.Background()

	u, err := svc.ResolveExternalLogin(ctx, &ExternalLoginInput{
		TenantID: 1, ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-fresh",
		Username: "fresh", AutoCreate: true,
	})
	if err != nil {
		t.Fatalf("expected auto-create to succeed for a never-bound external id, got: %v", err)
	}
	if u == nil || u.Username == "" {
		t.Fatal("expected a provisioned user back")
	}
}

// TestResolveExternalLoginNoBindingNoAutoCreateIsNotLinked pins the existing
// !AutoCreate branch stays intact: a genuinely fresh external id with
// AutoCreate off still gets ErrExternalUserNotLinked, not ErrExternalUserDeleted.
func TestResolveExternalLoginNoBindingNoAutoCreateIsNotLinked(t *testing.T) {
	svc, _, _ := newDeleteCascadeTestService(t)
	ctx := context.Background()

	_, err := svc.ResolveExternalLogin(ctx, &ExternalLoginInput{
		TenantID: 1, ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-never",
		Username: "never", AutoCreate: false,
	})
	if !errors.Is(err, ErrExternalUserNotLinked) {
		t.Fatalf("want ErrExternalUserNotLinked, got %v", err)
	}
}

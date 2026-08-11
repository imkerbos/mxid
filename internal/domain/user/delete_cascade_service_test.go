package user

// The repository-level test in delete_cascade_test.go pins the sweep
// mechanics but calls SoftDeleteIdentitiesByUser directly, so it never
// exercises the ordering the incident actually turned on: Service.Delete
// must sweep bindings BEFORE soft-deleting the user, not after. This file
// assembles a real Service over the same in-memory-sqlite repository and
// drives it through Delete.
//
// Note on what these tests do and don't prove: SoftDeleteIdentitiesByUser is
// an unconditional `UPDATE ... WHERE user_id = ?` with no dependency on
// whether the user row is still live. That means the happy-path end state
// (no live bindings, user gone, bindings listed as deleted) is identical
// under EITHER ordering of the two statements in Service.Delete — reversing
// them would not change what a passing run observes. Only
// TestServiceDeleteLeavesBindingsSweptWhenUserDeleteFails below actually
// pins the ordering: it injects a failure into the user delete step and
// checks what state that failure leaves behind, which is observably
// different depending on which statement ran first.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newDeleteCascadeTestService(t *testing.T) (*Service, Repository, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewGormRepository(db)
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("new id gen: %v", err)
	}
	svc := NewService(repo, idGen, event.NewBus(zap.NewNop()), &bootstrap.SecurityConfig{}, nil, "")
	return svc, repo, db
}

// TestServiceDeleteSweepsIdentitiesBeforeDeletingUser pins the happy-path end
// state Service.Delete must reach: no live bindings survive the user, and
// the swept ones are still recoverable through ListDeletedIdentities — the
// console restore path Task 6 built. It does NOT pin the ordering of the two
// statements in Service.Delete — see the file-level note above and
// TestServiceDeleteLeavesBindingsSweptWhenUserDeleteFails for that.
func TestServiceDeleteSweepsIdentitiesBeforeDeletingUser(t *testing.T) {
	svc, repo, db := newDeleteCascadeTestService(t)
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

	if err := svc.Delete(ctx, 1); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// The user itself must be gone from ordinary lookups (soft-deleted).
	if _, err := repo.GetByID(ctx, 1); err == nil {
		t.Fatal("deleted user must not be visible through GetByID")
	}

	live, err := repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list live identities: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("no live bindings must survive user deletion, got %d", len(live))
	}

	gone, err := repo.ListDeletedIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list deleted identities: %v", err)
	}
	if len(gone) != 1 || gone[0].ID != 10 {
		t.Fatalf("swept binding must remain recoverable, got %+v", gone)
	}
}

// TestServiceDeleteWithNoIdentitiesStillSucceeds guards against the sweep
// step turning "delete a user who never had any bindings" into an error —
// the overwhelmingly common case in production.
func TestServiceDeleteWithNoIdentitiesStillSucceeds(t *testing.T) {
	svc, repo, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 2, TenantID: 1, Username: "no-bindings", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	if err := svc.Delete(ctx, 2); err != nil {
		t.Fatalf("delete a user with no bindings must succeed, got: %v", err)
	}
	if _, err := repo.GetByID(ctx, 2); err == nil {
		t.Fatal("deleted user must not be visible through GetByID")
	}
}

// deleteFailingRepo wraps a real Repository and forces its Delete (the user
// soft delete) to fail, while every other method — including
// SoftDeleteIdentitiesByUser — passes through untouched. This is failure
// injection, not a call-order spy: it does not record which method ran, it
// makes the second statement in Service.Delete blow up and then inspects
// what state that leaves behind. That is the property that actually
// distinguishes the two orderings — see the file-level note above.
type deleteFailingRepo struct {
	Repository
	err error
}

func (f *deleteFailingRepo) Delete(ctx context.Context, id int64) error {
	return f.err
}

// TestServiceDeleteLeavesBindingsSweptWhenUserDeleteFails is the actual
// ordering guard. It injects a failure into the user-delete step and checks
// what Service.Delete leaves behind:
//
//   - Under the correct order (sweep, then delete-user), the sweep already
//     committed by the time the injected failure happens. Live bindings are
//     therefore already gone and the binding is already listed as
//     soft-deleted/recoverable — "user present, bindings restorable", the
//     safe state the brief calls out.
//   - Under the reversed order (delete-user, then sweep), the injected
//     failure on the user delete would abort Service.Delete before the sweep
//     ever ran, so the binding would still be live. That is an observably
//     different, and worse, outcome: exactly the orphaned-binding shape from
//     the production incident, just with the roles swapped (here the user
//     row is intact and the failure is synthetic, but the property under
//     test — does the sweep depend on the user delete having already
//     failed-safe — is the same one that mattered in production).
//
// This test was verified to fail when the two statements in Service.Delete
// were temporarily reversed; see the task report for the captured output.
func TestServiceDeleteLeavesBindingsSweptWhenUserDeleteFails(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	realRepo := NewGormRepository(db)
	injected := errors.New("simulated user delete failure")
	repo := &deleteFailingRepo{Repository: realRepo, err: injected}

	idGen, genErr := snowflake.New(1)
	if genErr != nil {
		t.Fatalf("new id gen: %v", genErr)
	}
	svc := NewService(repo, idGen, event.NewBus(zap.NewNop()), &bootstrap.SecurityConfig{}, nil, "")

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.Create(&User{ID: 3, TenantID: 1, Username: "layne-3", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 30, UserID: 3, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-3",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	err = svc.Delete(ctx, 3)
	if err == nil {
		t.Fatal("expected the injected user-delete failure to surface")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("expected the injected error to be wrapped through, got: %v", err)
	}

	// The user row must still be there — the delete never committed.
	if _, err := realRepo.GetByID(ctx, 3); err != nil {
		t.Fatalf("user must still be present after a failed delete, got: %v", err)
	}

	// If the sweep ran first (the required order), the binding is already
	// gone from live listings and already sitting in the recoverable
	// soft-deleted list, regardless of the later failure.
	live, err := realRepo.ListIdentities(ctx, 3)
	if err != nil {
		t.Fatalf("list live identities: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("sweep must have already run before the user-delete step failed, got %d live bindings", len(live))
	}
	gone, err := realRepo.ListDeletedIdentities(ctx, 3)
	if err != nil {
		t.Fatalf("list deleted identities: %v", err)
	}
	if len(gone) != 1 || gone[0].ID != 30 {
		t.Fatalf("swept binding must be recoverable even though the user delete failed, got %+v", gone)
	}
}

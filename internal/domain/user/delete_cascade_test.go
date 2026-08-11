package user

// mxid_user_identity's FK is ON DELETE CASCADE, but user deletion is a soft
// delete — an UPDATE — and UPDATE does not fire CASCADE. The bindings were left
// orphaned, pointing at a user nobody could load. Deletion now sweeps them
// itself, in the application layer, because the database cannot.

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestDeleteUserSoftDeletesItsIdentities(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewGormRepository(db)
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

	if err := repo.SoftDeleteIdentitiesByUser(ctx, 1); err != nil {
		t.Fatalf("sweep identities: %v", err)
	}

	live, err := repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("deleting a user must not leave live bindings behind, got %d", len(live))
	}
	gone, err := repo.ListDeletedIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list deleted: %v", err)
	}
	if len(gone) != 1 {
		t.Fatalf("the binding must remain recoverable, got %d", len(gone))
	}
}

func TestRestoreUserBringsBackTheAccountButNotItsBindings(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewGormRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	// Delete through the same path Service.Delete takes: sweep bindings first,
	// then soft-delete the user (see TestDeleteUserSoftDeletesItsIdentities'
	// header comment for why the sweep has to happen in the app layer).
	if err := repo.SoftDeleteIdentitiesByUser(ctx, 1); err != nil {
		t.Fatalf("sweep identities: %v", err)
	}
	if err := repo.Delete(ctx, 1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, 1); err == nil {
		t.Fatal("deleted user must not be loadable")
	}

	if err := repo.RestoreUser(ctx, 1); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := repo.GetByID(ctx, 1); err != nil {
		t.Fatalf("restored user must be loadable: %v", err)
	}

	// The name's other half: restoring the user must NOT resurrect its
	// bindings. That is Service.RestoreIdentity's job, invoked separately and
	// separately audited — see the package comment at the top of this file.
	live, err := repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("restoring the user must not restore its bindings, got %d live", len(live))
	}
	gone, err := repo.ListDeletedIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list deleted identities: %v", err)
	}
	if len(gone) != 1 {
		t.Fatalf("the binding must still be sitting in the deleted set, got %d", len(gone))
	}
}

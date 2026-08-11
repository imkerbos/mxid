package user

// Unbinding an identity used to be a one-way door: the row was hard-deleted and
// no API could recreate it. These tests pin the round trip — unbind hides the
// binding, restore brings it back — and the guard that stops a restore from
// silently stealing an external account away from a live user.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newIdentityTestRepo(t *testing.T) (Repository, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewGormRepository(db), db
}

func seedIdentity(t *testing.T, db *gorm.DB, id, userID int64, externalID string) *UserIdentity {
	t.Helper()
	now := time.Now().UTC()
	i := &UserIdentity{
		ID: id, UserID: userID, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: externalID,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(i).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return i
}

func TestUnbindThenRestoreRoundTrip(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()
	seedIdentity(t, db, 10, 1, "ext-1")

	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	live, err := repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("unbind must hide the binding, still see %d", len(live))
	}

	gone, err := repo.ListDeletedIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list deleted: %v", err)
	}
	if len(gone) != 1 || gone[0].ID != 10 {
		t.Fatalf("unbound binding must remain recoverable, got %+v", gone)
	}

	if err := repo.RestoreIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("restore: %v", err)
	}

	live, err = repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list live after restore: %v", err)
	}
	if len(live) != 1 || live[0].ID != 10 {
		t.Fatalf("restore must bring the binding back, got %+v", live)
	}
}

func TestRestoreRefusesWhenExternalIDTakenByLiveBinding(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()

	seedIdentity(t, db, 10, 1, "ext-1")
	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	// Someone else picked up the same external account in the meantime.
	seedIdentity(t, db, 11, 2, "ext-1")

	err := repo.RestoreIdentity(ctx, 1, 10)
	if err == nil {
		t.Fatal("restore must refuse: ext-1 now belongs to a live binding on another user")
	}
	if !errors.Is(err, ErrExternalIDTaken) {
		t.Fatalf("want ErrExternalIDTaken, got %v", err)
	}
}

func TestGetIdentityByExternalIgnoresSoftDeleted(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()
	seedIdentity(t, db, 10, 1, "ext-1")
	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	if _, err := repo.GetIdentityByExternal(ctx, 1, "lark", "p1", "ext-1"); err == nil {
		t.Fatal("live lookup must not see a soft-deleted binding")
	}
	got, err := repo.GetAnyIdentityByExternal(ctx, 1, "lark", "p1", "ext-1")
	if err != nil {
		t.Fatalf("unscoped lookup must still find it: %v", err)
	}
	if got.ID != 10 {
		t.Fatalf("want binding 10, got %d", got.ID)
	}
}

// TestRestoreSurfacesTypedErrorOnIndexRace pins the case ruling 3 called out:
// the occupancy check inside RestoreIdentity is read-then-write, so a
// concurrent first-time external login can insert a fresh live binding for
// the same external id in the gap between the check and the update. In
// production the partial unique index uk_user_identity_external (migration
// 000068) is the real backstop that catches this — it is not created by
// AutoMigrate (it's hand-rolled SQL, not a struct tag), so it is created here
// explicitly to mirror production schema. A gorm "before update" hook fires
// the racing insert at the exact moment between RestoreIdentity's Count check
// and its Updates call, deterministically reproducing the race without real
// goroutines. The assertion is that the driver's raw unique-violation error
// is translated to ErrExternalIDTaken, not leaked to the caller.
func TestRestoreSurfacesTypedErrorOnIndexRace(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()

	if err := db.Exec(`CREATE UNIQUE INDEX uk_user_identity_external
		ON mxid_user_identity (tenant_id, provider_type, external_id)
		WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("create partial unique index: %v", err)
	}

	seedIdentity(t, db, 10, 1, "ext-1")
	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	raced := false
	db.Callback().Update().Before("gorm:update").Register("test:racing-insert", func(tx *gorm.DB) {
		if raced {
			return
		}
		raced = true
		now := time.Now().UTC()
		// Use tx, not db: gorm wraps this Updates call in an implicit
		// transaction that already holds the connection, so a query issued
		// through db (a fresh checkout from the same single-connection pool)
		// would deadlock waiting for a connection the transaction is holding.
		// tx is that same in-flight transaction handle.
		if err := tx.Exec(
			`INSERT INTO mxid_user_identity (id, user_id, tenant_id, provider_type, provider_id, external_id, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			11, 2, 1, "lark", "p1", "ext-1", now, now,
		).Error; err != nil {
			t.Fatalf("racing insert: %v", err)
		}
	})

	err := repo.RestoreIdentity(ctx, 1, 10)
	if !raced {
		t.Fatal("race hook never fired, test did not exercise the intended window")
	}
	if !errors.Is(err, ErrExternalIDTaken) {
		t.Fatalf("want the index violation surfaced as ErrExternalIDTaken, got %v", err)
	}
}

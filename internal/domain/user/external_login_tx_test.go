package user

// The point of CreateWithIdentity is atomicity, and atomicity is only visible
// when something fails. A test that just checks the happy path would pass
// equally well against the three-separate-writes version it replaced.

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTxTestRepo(t *testing.T) (Repository, *gorm.DB) {
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

func txFixtures(now time.Time) (*User, *UserDetail, *UserIdentity) {
	u := &User{ID: 1, TenantID: 1, Username: "alice", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}
	d := &UserDetail{ID: 2, UserID: 1, CreatedAt: now, UpdatedAt: now}
	i := &UserIdentity{
		ID: 3, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}
	return u, d, i
}

func TestCreateWithIdentityWritesAllThree(t *testing.T) {
	repo, db := newTxTestRepo(t)
	u, d, i := txFixtures(time.Now().UTC())

	if err := repo.CreateWithIdentity(context.Background(), u, d, i); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, c := range []struct {
		name  string
		model any
	}{{"user", &User{}}, {"detail", &UserDetail{}}, {"identity", &UserIdentity{}}} {
		var n int64
		if err := db.Model(c.model).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", c.name, err)
		}
		if n != 1 {
			t.Fatalf("%s rows = %d, want 1", c.name, n)
		}
	}
}

// The case that produced ghost accounts: the identity write fails, and the user
// row must not survive it. Forced by pre-inserting a row with the identity's
// primary key so the insert inside the transaction collides.
func TestCreateWithIdentityRollsBackTheUserWhenIdentityFails(t *testing.T) {
	repo, db := newTxTestRepo(t)
	now := time.Now().UTC()

	blocker := &UserIdentity{
		ID: 3, UserID: 999, TenantID: 1,
		ProviderType: "lark", ProviderID: "p0", ExternalID: "other",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(blocker).Error; err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	u, d, i := txFixtures(now)
	if err := repo.CreateWithIdentity(context.Background(), u, d, i); err == nil {
		t.Fatal("expected the identity insert to fail on the duplicate key")
	}

	// No orphan user, and therefore no seat consumed and no suffixed retry on
	// the next login.
	var users int64
	if err := db.Model(&User{}).Count(&users).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Fatalf("user row survived a failed identity write: %d rows", users)
	}
	var details int64
	if err := db.Model(&UserDetail{}).Count(&details).Error; err != nil {
		t.Fatalf("count details: %v", err)
	}
	if details != 0 {
		t.Fatalf("detail row survived a failed identity write: %d rows", details)
	}
}

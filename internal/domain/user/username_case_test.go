package user

// `alice` and `Alice` are one person, so they are one account. That is a
// schema fact (migration 000070) and a lookup fact (GetByUsername), and this
// suite pins the second: the index can only refuse a bad write, it cannot make
// sign-in accept the casing someone actually typed.

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newUsernameCaseRepo(t *testing.T) Repository {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now().UTC()
	if err := db.Create(&User{
		ID: 10, TenantID: 1, Username: "Alice", PasswordHash: "x",
		Status: StatusActive, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return NewGormRepository(db)
}

// Sign-in must accept whichever casing the person typed. Nobody types their
// own name with consistent capitalisation, and a login that refuses `alice`
// because the account was created as `Alice` is indistinguishable, to the
// person in front of it, from a wrong password.
func TestGetByUsername_IsCaseInsensitive(t *testing.T) {
	repo := newUsernameCaseRepo(t)
	for _, typed := range []string{"Alice", "alice", "ALICE", "aLiCe"} {
		u, err := repo.GetByUsername(context.Background(), 1, typed)
		if err != nil {
			t.Fatalf("GetByUsername(%q): %v", typed, err)
		}
		if u.ID != 10 {
			t.Fatalf("GetByUsername(%q) = user %d, want 10", typed, u.ID)
		}
	}
}

// A different tenant's identically-named account must not be reachable. The
// case-folding widens the match on the name; it must not widen it past the
// tenant.
func TestGetByUsername_StillScopedToTenant(t *testing.T) {
	repo := newUsernameCaseRepo(t)
	if _, err := repo.GetByUsername(context.Background(), 2, "alice"); err == nil {
		t.Fatal("found a user from another tenant")
	}
}

// The duplicate check Create performs runs through the same lookup, so a name
// that differs only by case is reported as taken rather than being written and
// then refused by the index.
func TestGetByUsername_CatchesCaseVariantDuplicate(t *testing.T) {
	repo := newUsernameCaseRepo(t)
	if _, err := repo.GetByUsername(context.Background(), 1, "alice"); err != nil {
		t.Fatalf("a case variant of an existing name must read as taken: %v", err)
	}
}

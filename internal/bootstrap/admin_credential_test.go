package bootstrap

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// seededAdminDB builds a one-table stand-in holding the account exactly as
// migration 000009 seeds it.
func seededAdminDB(t *testing.T, hash string, status int) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec(`CREATE TABLE mxid_user (
		username TEXT, password_hash TEXT, status INTEGER,
		must_change_pwd BOOLEAN, password_changed_at DATETIME, updated_at DATETIME)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	if err := db.Exec(`INSERT INTO mxid_user VALUES ('admin', ?, ?, 0, NULL, NULL)`,
		hash, status).Error; err != nil {
		t.Fatalf("seed row: %v", err)
	}
	return db
}

// Explicit column tags: the same rule the rest of the codebase follows, because
// garble renames fields in EE builds and an untagged one scans empty.
type adminRow struct {
	PasswordHash  string `gorm:"column:password_hash"`
	Status        int    `gorm:"column:status"`
	MustChangePwd bool   `gorm:"column:must_change_pwd"`
}

func readAdmin(t *testing.T, db *gorm.DB) adminRow {
	t.Helper()
	var r adminRow
	if err := db.Raw(`SELECT password_hash, status, must_change_pwd FROM mxid_user WHERE username='admin'`).
		Scan(&r).Error; err != nil {
		t.Fatalf("read admin: %v", err)
	}
	return r
}

// Without a chosen password there is nothing safe to do but take the account
// out of service. Leaving it merely gated would not be enough: anyone who has
// read the repository knows the password, and a gated session can still reach
// the change-password endpoint — which is an account takeover, not a blocked
// login.
func TestSecureSeededAdmin_LocksWhenNoPasswordChosen(t *testing.T) {
	db := seededAdminDB(t, seededAdminHash, statusActive)

	if err := SecureSeededAdmin(context.Background(), db, nil, true, ""); err != nil {
		t.Fatalf("SecureSeededAdmin: %v", err)
	}

	got := readAdmin(t, db)
	if got.Status != statusLocked {
		t.Errorf("status = %d, want %d (locked)", got.Status, statusLocked)
	}
	if !got.MustChangePwd {
		t.Error("must_change_pwd was not set")
	}
	if got.PasswordHash != seededAdminHash {
		t.Error("the password was changed even though none was chosen")
	}
}

func TestSecureSeededAdmin_AppliesChosenPasswordAndUnlocks(t *testing.T) {
	// Starts locked, as a previous boot without the variable would have left it.
	db := seededAdminDB(t, seededAdminHash, statusLocked)

	const chosen = "Chosen@Password2026"
	if err := SecureSeededAdmin(context.Background(), db, nil, true, chosen); err != nil {
		t.Fatalf("SecureSeededAdmin: %v", err)
	}

	got := readAdmin(t, db)
	if got.PasswordHash == seededAdminHash {
		t.Fatal("the published password is still in place")
	}
	if !crypto.CheckPassword(chosen, got.PasswordHash) {
		t.Error("the account does not accept the chosen password")
	}
	if got.Status != statusActive {
		t.Errorf("status = %d, want %d — a lock from an earlier boot was not lifted", got.Status, statusActive)
	}
	// The problem being fixed is that the password was PUBLISHED. The variable
	// likely sits in a deployment manifest more people can read than should
	// know it, so a change is still owed.
	if !got.MustChangePwd {
		t.Error("must_change_pwd was cleared — the operator's variable became the standing password")
	}
}

// An operator who has already chosen their own password must not be touched,
// however weak or strong it is. bcrypt salts every hash, so the equality test
// identifies the seeded row and nothing else.
func TestSecureSeededAdmin_LeavesAChangedPasswordAlone(t *testing.T) {
	own, err := crypto.HashPassword("an-operator-chose-this")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	db := seededAdminDB(t, own, statusActive)

	if err := SecureSeededAdmin(context.Background(), db, nil, true, "something-else"); err != nil {
		t.Fatalf("SecureSeededAdmin: %v", err)
	}

	got := readAdmin(t, db)
	if got.PasswordHash != own {
		t.Error("an already-changed password was overwritten")
	}
	if got.Status != statusActive || got.MustChangePwd {
		t.Errorf("an untouched account was modified: status=%d must_change=%v", got.Status, got.MustChangePwd)
	}
}

// Another account using the same weak password hashes differently — bcrypt
// salts — so it is not mistaken for the seeded one.
func TestSecureSeededAdmin_DoesNotMatchTheSamePasswordHashedSeparately(t *testing.T) {
	same, err := crypto.HashPassword("admin123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if same == seededAdminHash {
		t.Fatal("bcrypt produced an identical hash for the same password — the salt is not working")
	}
	db := seededAdminDB(t, same, statusActive)

	if err := SecureSeededAdmin(context.Background(), db, nil, true, ""); err != nil {
		t.Fatalf("SecureSeededAdmin: %v", err)
	}
	if got := readAdmin(t, db); got.Status != statusActive {
		t.Error("an account that merely shares the password was locked")
	}
}

// The seeded password is what the README, the demo seed and the smoke tests are
// built around. Rotating or locking it under a developer would break all three
// to protect a database on their laptop.
func TestSecureSeededAdmin_LeavesDebugBuildsAlone(t *testing.T) {
	db := seededAdminDB(t, seededAdminHash, statusActive)

	if err := SecureSeededAdmin(context.Background(), db, nil, false, ""); err != nil {
		t.Fatalf("SecureSeededAdmin: %v", err)
	}

	got := readAdmin(t, db)
	if got.PasswordHash != seededAdminHash || got.Status != statusActive || got.MustChangePwd {
		t.Errorf("a debug build was modified: status=%d must_change=%v hash_changed=%v",
			got.Status, got.MustChangePwd, got.PasswordHash != seededAdminHash)
	}
}

// Several replicas booting at once must not each report having done something.
// Every write is conditional on the seeded hash, so the second pass matches no
// rows.
func TestSecureSeededAdmin_IsIdempotent(t *testing.T) {
	db := seededAdminDB(t, seededAdminHash, statusActive)
	ctx := context.Background()

	for range 3 {
		if err := SecureSeededAdmin(ctx, db, nil, true, "Chosen@Password2026"); err != nil {
			t.Fatalf("SecureSeededAdmin: %v", err)
		}
	}

	got := readAdmin(t, db)
	if !crypto.CheckPassword("Chosen@Password2026", got.PasswordHash) {
		t.Error("repeated runs left the account unusable")
	}
}

func TestSecureSeededAdmin_NilDBIsNotAnError(t *testing.T) {
	if err := SecureSeededAdmin(context.Background(), nil, nil, true, ""); err != nil {
		t.Errorf("nil db: %v", err)
	}
}

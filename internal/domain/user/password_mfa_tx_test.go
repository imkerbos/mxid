package user

// Both transactions exist for their failure paths. The happy paths were already
// correct before the wrapping, so a test that only asserted them would pass
// against the split-write versions these replaced.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newPwdMFARepo(t *testing.T) (Repository, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserPasswordHistory{}, &UserMFA{}, &MFABackupCode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewGormRepository(db), db
}

func seedUser(t *testing.T, db *gorm.DB) *User {
	t.Helper()
	now := time.Now().UTC()
	u := &User{ID: 1, TenantID: 1, Username: "alice", PasswordHash: "old", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestResetPasswordTxWritesHashFlagAndHistory(t *testing.T) {
	repo, db := newPwdMFARepo(t)
	seedUser(t, db)
	now := time.Now().UTC()

	h := &UserPasswordHistory{ID: 10, UserID: 1, PasswordHash: "new", CreatedAt: now}
	if err := repo.ResetPasswordTx(context.Background(), 1, "new", true, h); err != nil {
		t.Fatalf("reset: %v", err)
	}

	var got User
	if err := db.First(&got, 1).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if got.PasswordHash != "new" {
		t.Fatalf("password_hash = %q, want %q", got.PasswordHash, "new")
	}
	if !got.MustChangePwd {
		t.Fatal("must_change_pwd was not set, so an admin-issued temporary password would become permanent")
	}
	var n int64
	if err := db.Model(&UserPasswordHistory{}).Count(&n).Error; err != nil {
		t.Fatalf("count history: %v", err)
	}
	if n != 1 {
		t.Fatalf("history rows = %d, want 1", n)
	}
}

// mustChange=false must leave the flag alone rather than clearing it: the caller
// is opting out of forcing a change, not asserting the user has none pending.
func TestResetPasswordTxLeavesTheFlagAloneWhenNotForcing(t *testing.T) {
	repo, db := newPwdMFARepo(t)
	seedUser(t, db)
	if err := db.Model(&User{}).Where("id = ?", 1).Update("must_change_pwd", true).Error; err != nil {
		t.Fatalf("preset flag: %v", err)
	}

	h := &UserPasswordHistory{ID: 10, UserID: 1, PasswordHash: "new", CreatedAt: time.Now().UTC()}
	if err := repo.ResetPasswordTx(context.Background(), 1, "new", false, h); err != nil {
		t.Fatalf("reset: %v", err)
	}

	var got User
	if err := db.First(&got, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !got.MustChangePwd {
		t.Fatal("mustChange=false cleared a pending must-change flag")
	}
}

// The failure that mattered: history insert fails, and the new password must not
// survive it. Otherwise the password is live but unrecorded, so the reuse policy
// — which only knows what history records — would let it be set again forever.
func TestResetPasswordTxRollsBackThePasswordWhenHistoryFails(t *testing.T) {
	repo, db := newPwdMFARepo(t)
	seedUser(t, db)
	now := time.Now().UTC()

	blocker := &UserPasswordHistory{ID: 10, UserID: 999, PasswordHash: "other", CreatedAt: now}
	if err := db.Create(blocker).Error; err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	h := &UserPasswordHistory{ID: 10, UserID: 1, PasswordHash: "new", CreatedAt: now}
	if err := repo.ResetPasswordTx(context.Background(), 1, "new", true, h); err == nil {
		t.Fatal("expected the history insert to fail on the duplicate key")
	}

	var got User
	if err := db.First(&got, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.PasswordHash != "old" {
		t.Fatalf("password_hash = %q after a failed history write, want the original %q", got.PasswordHash, "old")
	}
	if got.MustChangePwd {
		t.Fatal("must_change_pwd survived the rollback")
	}
}

func TestResetPasswordTxReportsAMissingUser(t *testing.T) {
	repo, _ := newPwdMFARepo(t)
	h := &UserPasswordHistory{ID: 10, UserID: 42, PasswordHash: "new", CreatedAt: time.Now().UTC()}
	err := repo.ResetPasswordTx(context.Background(), 42, "new", true, h)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func seedTOTPWithCodes(t *testing.T, db *gorm.DB) {
	t.Helper()
	now := time.Now().UTC()
	secret := "s3cr3t"
	rows := []*UserMFA{
		{ID: 1, UserID: 1, Type: MFATypeTotp, Secret: &secret, Verified: true, CreatedAt: now, UpdatedAt: now},
		{ID: 2, UserID: 1, Type: MFATypeSMS, Verified: true, CreatedAt: now, UpdatedAt: now},
	}
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed mfa: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		c := &MFABackupCode{ID: int64(100 + i), UserID: 1, CodeHash: "h", CreatedAt: now}
		if err := db.Create(c).Error; err != nil {
			t.Fatalf("seed backup code: %v", err)
		}
	}
}

func TestDeleteMFATxRemovesTheFactorAndItsBackupCodes(t *testing.T) {
	repo, db := newPwdMFARepo(t)
	seedTOTPWithCodes(t, db)

	if err := repo.DeleteMFATx(context.Background(), 1, MFATypeTotp); err != nil {
		t.Fatalf("delete: %v", err)
	}

	var codes int64
	if err := db.Model(&MFABackupCode{}).Count(&codes).Error; err != nil {
		t.Fatalf("count codes: %v", err)
	}
	if codes != 0 {
		t.Fatalf("%d backup codes still authenticate after the factor was removed", codes)
	}
}

// A user can hold TOTP and SMS at once. Removing one must not remove the other —
// the un-scoped first draft of this method would have silently disabled SMS too.
func TestDeleteMFATxLeavesOtherFactorsInPlace(t *testing.T) {
	repo, db := newPwdMFARepo(t)
	seedTOTPWithCodes(t, db)

	if err := repo.DeleteMFATx(context.Background(), 1, MFATypeTotp); err != nil {
		t.Fatalf("delete: %v", err)
	}

	var remaining []UserMFA
	if err := db.Find(&remaining).Error; err != nil {
		t.Fatalf("list mfa: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Type != MFATypeSMS {
		t.Fatalf("remaining factors = %+v, want only the SMS one", remaining)
	}
}

// Matches the non-transactional DeleteMFA so callers that distinguish
// "no such factor" from "removed" keep behaving the same.
func TestDeleteMFATxReportsAMissingFactor(t *testing.T) {
	repo, db := newPwdMFARepo(t)
	seedUser(t, db)

	err := repo.DeleteMFATx(context.Background(), 1, MFATypeTotp)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("err = %v, want gorm.ErrRecordNotFound", err)
	}
}

package bootstrap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// seededAdminHash is the bcrypt hash migration 000009 seeds the `admin` account
// with. The plaintext behind it is written in that migration's first line, in a
// public repository — so this constant identifies "an account still carrying a
// password the whole internet knows", which is the only thing it is used for.
//
// bcrypt salts every hash, so an equality test matches exactly the row seeded by
// that migration. Another account that happens to use the same weak password
// hashes differently and is left alone.
const seededAdminHash = "$2a$10$L/vj.Fxj8KyX93.ANmRrMONzQBRtWwTgd/X8ZGH.XW4Nv5ATRienS"

// BootstrapAdminPasswordEnv names the environment variable that sets the
// initial administrator password on a release deployment.
const BootstrapAdminPasswordEnv = "MXID_BOOTSTRAP_ADMIN_PASSWORD"

// statusLocked mirrors user.StatusLocked. Duplicated rather than imported
// because internal/domain/user imports this package's App, and depending back
// on it would be a cycle.
const statusLocked = 2

// statusActive mirrors user.StatusActive, for the same reason.
const statusActive = 1

// SecureSeededAdmin makes sure no release deployment serves with the seeded
// administrator credential.
//
// Migration 000009 seeds `admin` with a password written in plaintext in that
// migration, in a public repository, and until now nothing changed it, warned
// about it, or forced it to be changed. Every production install started with a
// super-admin credential that any reader of the source already had.
//
// In release mode, an account still carrying that hash is dealt with before the
// server accepts a request:
//
//   - MXID_BOOTSTRAP_ADMIN_PASSWORD set — the account takes that password, stays
//     usable, and keeps must_change_pwd so whoever signs in must still choose
//     their own (see authn.PwdGateMiddleware).
//   - not set — the account is LOCKED. Leaving it merely gated would not be
//     enough: anyone who knows the published password could sign in and set a
//     new one, which is an account takeover rather than a blocked login. Other
//     administrators are unaffected, the server starts normally, and one restart
//     with the variable set restores the account.
//
// Deliberately NOT generating a password and printing it: the logger redacts
// any field whose key looks like a credential (internal/bootstrap/logger.go), so
// a generated password would arrive at the operator as "***" — and defeating
// that filter to ship a secret into the log pipeline is the wrong trade.
//
// Debug builds are untouched. The seeded password is what the README, the demo
// seed and the smoke tests are built around, and interfering with it under a
// developer would break all three to protect a database on their laptop.
//
// Safe under concurrent startup: every write is conditional on the seeded hash,
// so with several replicas booting at once the losers match no rows and say
// nothing.
func SecureSeededAdmin(ctx context.Context, db *gorm.DB, logger *zap.Logger, releaseMode bool, envPassword string) error {
	if db == nil {
		return nil
	}

	var count int64
	if err := db.WithContext(ctx).
		Table("mxid_user").
		Where("username = ? AND password_hash = ?", "admin", seededAdminHash).
		Count(&count).Error; err != nil {
		return fmt.Errorf("check seeded admin credential: %w", err)
	}
	if count == 0 {
		return nil // already changed, or this install never had it
	}

	if !releaseMode {
		if logger != nil {
			logger.Warn("the seeded admin password is still in place — expected in development, " +
				"but a release deployment will refuse to serve with it; set " +
				BootstrapAdminPasswordEnv + " before deploying")
		}
		return nil
	}

	password := strings.TrimSpace(envPassword)
	if password == "" {
		return lockSeededAdmin(ctx, db, logger)
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	now := time.Now()
	res := db.WithContext(ctx).
		Table("mxid_user").
		Where("username = ? AND password_hash = ?", "admin", seededAdminHash).
		Updates(map[string]any{
			"password_hash":       hash,
			"password_changed_at": now,
			// Whoever signs in with this still has to choose their own. What is
			// being fixed here is that the password was PUBLISHED, not that it
			// was weak — and the variable is likely to sit in a deployment
			// manifest that more people can read than should know the password.
			"must_change_pwd": true,
			// Undo a lock left by a previous boot that had no variable set.
			"status":     statusActive,
			"updated_at": now,
		})
	if res.Error != nil {
		return fmt.Errorf("replace seeded admin credential: %w", res.Error)
	}
	if res.RowsAffected > 0 && logger != nil {
		logger.Info("seeded admin password replaced from "+BootstrapAdminPasswordEnv,
			zap.String("username", "admin"),
			zap.String("next", "a password change is still required at first sign-in"))
	}
	return nil
}

// lockSeededAdmin disables an account still holding the published password.
func lockSeededAdmin(ctx context.Context, db *gorm.DB, logger *zap.Logger) error {
	res := db.WithContext(ctx).
		Table("mxid_user").
		Where("username = ? AND password_hash = ? AND status <> ?", "admin", seededAdminHash, statusLocked).
		Updates(map[string]any{
			"status":          statusLocked,
			"must_change_pwd": true,
			"updated_at":      time.Now(),
		})
	if res.Error != nil {
		return fmt.Errorf("lock seeded admin account: %w", res.Error)
	}
	if logger != nil {
		logger.Error("SEEDED ADMIN ACCOUNT LOCKED — it still holds the password published in the "+
			"public repository, and this is a release deployment",
			zap.String("username", "admin"),
			zap.String("risk", "anyone who has read the source could otherwise have signed in and "+
				"taken the account over by setting a new password"),
			zap.String("to_recover", "set "+BootstrapAdminPasswordEnv+" to a password of your "+
				"choosing and restart; the account unlocks and you will be asked to change it at "+
				"first sign-in"),
			zap.String("note", "other administrator accounts are unaffected"))
	}
	return nil
}

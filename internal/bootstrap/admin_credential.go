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

// statusActive mirrors user.StatusActive. Duplicated rather than imported
// because internal/domain/user imports this package's App, and depending back
// on it would be a cycle. (statusLocked lives in the test file — nothing in the
// production path writes a lock any more.)
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
//   - MXID_BOOTSTRAP_ADMIN_PASSWORD set — the account takes that password and
//     keeps must_change_pwd so whoever signs in must still choose their own
//     (see authn.PwdGateMiddleware).
//   - not set — the account stays usable and is flagged must_change_pwd, with a
//     loud warning in the log. It is NOT locked: a first deployment has no other
//     administrator, so locking the only account leaves nobody able to sign in
//     and no supported way to recover — the Helm chart does not even expose the
//     variable. An operator who cannot log in cannot fix anything, which is a
//     worse outcome than a first login that is forced straight into a password
//     change.
//
// An account locked by the previous behaviour is released here, so upgrading is
// enough to recover an install that was locked out by it.
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
		return flagSeededAdmin(ctx, db, logger)
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

// flagSeededAdmin leaves an account still holding the published password usable,
// but owing a password change, and releases it if a previous release locked it.
//
// An earlier version locked the account instead. That was wrong in the case that
// matters most — a first deployment, where `admin` is the ONLY account. Locking
// it left nobody able to sign in, and the documented way out (set
// BootstrapAdminPasswordEnv and restart) did not exist under Helm, whose chart
// never exposed the variable. An operator who cannot sign in cannot fix
// anything, including the password this was protecting.
//
// What is given up: someone who knows the published password can now reach a
// session. What they can reach WITH it is only the change-password endpoint —
// PwdGateMiddleware blocks every other route while must_change_pwd stands — so
// they can lock the real operator out of a fresh install, but not read or change
// anything in it. That requires them to reach the console before the operator
// completes the first sign-in, on a deployment the operator just created.
//
// The status write is unconditional on the current value so that upgrading is
// enough to recover an install locked by the previous behaviour. It is scoped to
// the seeded hash, so an administrator who already chose their own password is
// never touched. One case is knowingly imprecise: an `admin` that still holds
// the seeded password AND is locked by the brute-force limiter is released here
// too. Telling the two locks apart would need a provenance column and a
// migration; the account is gated to the change-password endpoint either way.
func flagSeededAdmin(ctx context.Context, db *gorm.DB, logger *zap.Logger) error {
	res := db.WithContext(ctx).
		Table("mxid_user").
		Where("username = ? AND password_hash = ?", "admin", seededAdminHash).
		Updates(map[string]any{
			"status":          statusActive,
			"must_change_pwd": true,
			"updated_at":      time.Now(),
		})
	if res.Error != nil {
		return fmt.Errorf("flag seeded admin account: %w", res.Error)
	}
	if res.RowsAffected > 0 && logger != nil {
		logger.Error("THE SEEDED ADMIN PASSWORD IS STILL IN PLACE on a release deployment — it is "+
			"published in a public repository, so anyone who has read the source has it",
			zap.String("username", "admin"),
			zap.String("mitigation", "the account owes a password change, so a session opened with "+
				"that password can reach nothing but the change-password endpoint"),
			zap.String("to_fix", "sign in as admin and change the password now, or set "+
				BootstrapAdminPasswordEnv+" and restart"),
			zap.String("note", "other administrator accounts are unaffected"))
	}
	return nil
}

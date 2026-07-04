package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP errors.
var (
	ErrMasterKeyMissing = errors.New("master key not configured")
	ErrMFAAlreadyExists = errors.New("totp already enrolled")
	ErrMFANotEnrolled   = errors.New("totp not enrolled")
	ErrMFAInvalidCode   = errors.New("invalid totp code")
)

// SetupTOTP starts TOTP enrollment for a user.
//
// Generates a fresh RFC 6238 secret (SHA1, 6 digits, 30s step — the algorithm
// every authenticator app supports), encrypts it with the master key, and
// persists an unverified mxid_user_mfa row. Returns the base32 secret for
// manual entry and an otpauth:// URL the caller renders as a QR code.
//
// Idempotency: if an unverified totp row already exists it's replaced (lets
// a user restart enrollment after closing the setup page). A verified row
// returns ErrMFAAlreadyExists — disable it first to re-enroll.
func (s *Service) SetupTOTP(ctx context.Context, userID int64) (secret, otpauthURL string, err error) {
	if s.masterKey == nil {
		return "", "", ErrMasterKeyMissing
	}

	u, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return "", "", ErrUserNotFound
		}
		return "", "", fmt.Errorf("get user: %w", err)
	}

	existing, err := s.repo.GetMFA(ctx, userID, MFATypeTotp)
	if err != nil && !dberr.IsNotFound(err) {
		return "", "", fmt.Errorf("get mfa: %w", err)
	}
	if existing != nil && existing.Verified {
		return "", "", ErrMFAAlreadyExists
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: u.Username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp key: %w", err)
	}

	encSecret, err := s.masterKey.Encrypt([]byte(key.Secret()))
	if err != nil {
		return "", "", fmt.Errorf("encrypt secret: %w", err)
	}

	now := time.Now()
	if existing != nil {
		existing.Secret = &encSecret
		existing.Verified = false
		existing.UpdatedAt = now
		if err := s.repo.UpdateMFA(ctx, existing); err != nil {
			return "", "", fmt.Errorf("update mfa: %w", err)
		}
	} else {
		mfa := &UserMFA{
			ID:        s.idGen.Generate(),
			UserID:    userID,
			Type:      MFATypeTotp,
			Secret:    &encSecret,
			Verified:  false,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.repo.CreateMFA(ctx, mfa); err != nil {
			return "", "", fmt.Errorf("create mfa: %w", err)
		}
	}

	return key.Secret(), key.URL(), nil
}

// VerifyTOTP validates a TOTP code.
//
// On the user's first verify after SetupTOTP, the row is promoted to
// verified=true and marked default (TOTP becomes the active second factor).
// Subsequent calls just confirm the code — used both by the security page
// (re-verify before sensitive actions) and the login MFA challenge step.
//
// Uses a ±1 step window (default in pquerna/otp) to tolerate small clock skew.
// Returns ErrMFAInvalidCode on mismatch — never reveal the secret or which
// row was queried.
func (s *Service) VerifyTOTP(ctx context.Context, userID int64, code string) error {
	if s.masterKey == nil {
		return ErrMasterKeyMissing
	}
	mfa, err := s.repo.GetMFA(ctx, userID, MFATypeTotp)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get mfa: %w", err)
	}
	if mfa.Secret == nil || *mfa.Secret == "" {
		return ErrMFANotEnrolled
	}

	plain, err := s.masterKey.Decrypt(*mfa.Secret)
	if err != nil {
		return fmt.Errorf("decrypt secret: %w", err)
	}

	// Validate-then-claim for single-use (replay) protection. We can't use
	// the bare totp.Validate because it never tells us WHICH step matched —
	// and we need the matched step to reject a previously-consumed code.
	// Walk the same ±skew window pquerna/otp uses, find the exact step that
	// validates, then atomically claim it (reject if already consumed).
	matchedStep, ok := s.matchTOTPStep(code, string(plain))
	if !ok {
		return ErrMFAInvalidCode
	}
	if !s.claimTOTPStep(ctx, userID, matchedStep) {
		// Code is cryptographically valid but its time-step was already
		// consumed in this window — a replay. Surface the same opaque error
		// as a wrong code so the response shape never distinguishes them.
		return ErrMFAInvalidCode
	}

	if !mfa.Verified {
		mfa.Verified = true
		mfa.IsDefault = true
		mfa.UpdatedAt = time.Now()
		if err := s.repo.UpdateMFA(ctx, mfa); err != nil {
			return fmt.Errorf("update mfa: %w", err)
		}
		// First-time enrollment: caller obtained the TOTP secret, scanned
		// the QR, proved possession via this verify. Backup codes are
		// generated separately on demand via /security/mfa/backup-codes
		// — keeping the verify response stable (no plaintext leakage in
		// the otherwise tiny 200 body, and the enroll modal explicitly
		// fetches codes before closing).
	}
	return nil
}

// HasVerifiedTOTP reports whether the user has an active TOTP factor. Used by
// the auth engine to decide if a login attempt needs an MFA challenge step.
func (s *Service) HasVerifiedTOTP(ctx context.Context, userID int64) (bool, error) {
	mfa, err := s.repo.GetMFA(ctx, userID, MFATypeTotp)
	if err != nil {
		if dberr.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get mfa: %w", err)
	}
	return mfa.Verified, nil
}

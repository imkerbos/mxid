package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// MFA challenge errors.
var (
	ErrMFAChallengeNotFound = errors.New("mfa challenge not found or expired")
	ErrMFAVerifyFailed      = errors.New("mfa verification failed")
	ErrMFANotConfigured     = errors.New("mfa verifier not configured")
)

// looksLikeBackupCode reports whether `code` resembles a backup recovery
// code (8 alphanumeric chars, optionally split by a hyphen) rather than
// a 6-digit TOTP. Used to decide whether to even attempt the backup
// consumption — keeps a typo'd "12345" from burning a recovery code on
// the off-chance bcrypt finds a (truncated, padded) match.
func looksLikeBackupCode(code string) bool {
	stripped := ""
	for _, r := range code {
		switch {
		case r == '-' || r == ' ':
			continue
		case r >= '0' && r <= '9':
			stripped += string(r)
		case r >= 'A' && r <= 'Z':
			return true // contains alpha → can't be TOTP
		case r >= 'a' && r <= 'z':
			return true
		default:
			return false
		}
	}
	return len(stripped) == 8 // 8 digits (still possible to be a backup code)
}

// MFAVerifier is the bridge the auth engine uses to query and validate the
// per-user MFA factors stored in the user domain. Implementations live in the
// user package — the engine doesn't import user to avoid cycles.
type MFAVerifier interface {
	HasVerifiedTOTP(ctx context.Context, userID int64) (bool, error)
	VerifyTOTP(ctx context.Context, userID int64, code string) error
	// ConsumeBackupCode validates and one-shot-consumes a recovery code.
	// Returns ErrMFAVerifyFailed (wrapped) for a mismatch so the engine
	// can treat the failure identically to a wrong TOTP code.
	ConsumeBackupCode(ctx context.Context, userID int64, code string) error
}

// mfaChallengePayload is the Redis-stored state between Login (password OK,
// MFA required) and VerifyMFAChallenge (second factor submitted). Holds just
// enough to recreate the session deterministically once the code is valid.
type mfaChallengePayload struct {
	UserID      int64  `json:"user_id"`
	TenantID    int64  `json:"tenant_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	AuthType    string `json:"auth_type"`
	Namespace   string `json:"namespace"`
	ClientIP    string `json:"client_ip"`
	UserAgent   string `json:"user_agent"`
}

const (
	mfaChallengePrefix = "mxid:mfa:chal:"
	mfaChallengeTTL    = 5 * time.Minute
	mfaChallengeBytes  = 32
)

// issueMFAChallenge mints a one-time MFA challenge token, stores the login
// state in Redis under a short TTL, and returns the token to the caller. The
// caller (handler) hands the token to the client; the client posts it back
// alongside the TOTP code to /auth/mfa/verify.
func (e *Engine) issueMFAChallenge(ctx context.Context, p *mfaChallengePayload) (string, error) {
	token, err := crypto.GenerateBase62(mfaChallengeBytes)
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	if err := e.rdb.Set(ctx, mfaChallengePrefix+token, raw, mfaChallengeTTL).Err(); err != nil {
		return "", fmt.Errorf("store challenge: %w", err)
	}
	return token, nil
}

// consumeMFAChallenge atomically reads and deletes the stored challenge state.
// Single-use semantics prevent replay: once a token has been used the next
// attempt fails with ErrMFAChallengeNotFound regardless of code validity.
func (e *Engine) consumeMFAChallenge(ctx context.Context, token string) (*mfaChallengePayload, error) {
	if token == "" {
		return nil, ErrMFAChallengeNotFound
	}
	raw, err := e.rdb.GetDel(ctx, mfaChallengePrefix+token).Result()
	if err != nil {
		return nil, ErrMFAChallengeNotFound
	}
	var p mfaChallengePayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	return &p, nil
}

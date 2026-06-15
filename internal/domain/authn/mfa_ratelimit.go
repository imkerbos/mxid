package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// MFA rate-limit constants. Defaults are intentionally hardcoded — the
// password-fail path uses LoginConfig but MFA hot paths are simpler and
// the values are operational rather than per-tenant policy. If a tenant
// needs a different setting we can lift these into LoginConfig later.
const (
	mfaFailWindow    = 5 * time.Minute
	mfaFailThreshold = 5
	mfaLockDuration  = 15 * time.Minute
)

// ErrMFARateLimited is returned when the caller has tripped the MFA
// rate-limit and must wait before retrying. RetryAfter is exposed via
// MFARateLimitError so handlers can surface a useful Retry-After header.
var ErrMFARateLimited = errors.New("too many MFA verification attempts; account temporarily locked")

// MFARateLimitError wraps ErrMFARateLimited with how long the lock has
// left. errors.Is(err, ErrMFARateLimited) still works.
type MFARateLimitError struct {
	RetryAfter time.Duration
}

func (e *MFARateLimitError) Error() string {
	return fmt.Sprintf("%s (retry after %s)", ErrMFARateLimited.Error(), e.RetryAfter.Truncate(time.Second))
}

func (e *MFARateLimitError) Is(target error) bool { return target == ErrMFARateLimited }

// MFARateLimiter is the public surface security_handler.verifyTOTP and
// engine.VerifyMFAChallenge share. Two counter scopes:
//
//	user → catches "attacker has the right password, tries TOTP codes"
//	ip   → catches "scripted scan against many users from one host"
//
// Either tripping locks both paths for mfaLockDuration. Success on a real
// code clears both counters.
type MFARateLimiter struct {
	rdb *redis.Client
}

func NewMFARateLimiter(rdb *redis.Client) *MFARateLimiter {
	return &MFARateLimiter{rdb: rdb}
}

// Check returns nil when the caller may attempt verification; returns an
// *MFARateLimitError when locked.
func (l *MFARateLimiter) Check(ctx context.Context, userID int64, ip string) error {
	if l == nil || l.rdb == nil {
		return nil
	}
	for _, key := range []string{userKey(userID), ipKey(ip)} {
		if key == "" {
			continue
		}
		ttl, err := l.rdb.TTL(ctx, key+":locked").Result()
		if err == nil && ttl > 0 {
			return &MFARateLimitError{RetryAfter: ttl}
		}
	}
	return nil
}

// RecordFailure bumps the fail counters; once the threshold is hit it
// sets a 15min lock key that Check sees. Counters auto-expire after
// mfaFailWindow so attacks that pause have to start over.
func (l *MFARateLimiter) RecordFailure(ctx context.Context, userID int64, ip string) {
	if l == nil || l.rdb == nil {
		return
	}
	for _, key := range []string{userKey(userID), ipKey(ip)} {
		if key == "" {
			continue
		}
		count, err := l.rdb.Incr(ctx, key).Result()
		if err != nil {
			continue
		}
		if count == 1 {
			l.rdb.Expire(ctx, key, mfaFailWindow)
		}
		if count >= mfaFailThreshold {
			l.rdb.Set(ctx, key+":locked", "1", mfaLockDuration)
		}
	}
}

// Reset clears both counters and the lock — called on a successful
// verification.
func (l *MFARateLimiter) Reset(ctx context.Context, userID int64, ip string) {
	if l == nil || l.rdb == nil {
		return
	}
	keys := []string{}
	if k := userKey(userID); k != "" {
		keys = append(keys, k, k+":locked")
	}
	if k := ipKey(ip); k != "" {
		keys = append(keys, k, k+":locked")
	}
	if len(keys) > 0 {
		l.rdb.Del(ctx, keys...)
	}
}

func userKey(userID int64) string {
	if userID == 0 {
		return ""
	}
	return "mxid:mfa_fail:user:" + strconv.FormatInt(userID, 10)
}

func ipKey(ip string) string {
	if ip == "" {
		return ""
	}
	return "mxid:mfa_fail:ip:" + ip
}

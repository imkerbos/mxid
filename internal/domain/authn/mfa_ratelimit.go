package authn

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/mfaerr"
)

// MFA rate-limit constants. Defaults are intentionally hardcoded — the
// password-fail path uses LoginConfig but MFA hot paths are simpler and
// the values are operational rather than per-tenant policy. If a tenant
// needs a different setting we can lift these into LoginConfig later.
//
// The threshold is a usability budget, not a security one. A six-digit TOTP
// accepted across a ±1 step window leaves 3 valid codes in 10^6, so a guess
// lands with probability 3e-6. At 15 attempts per lock cycle an attacker needs
// centuries; at 5 they needed centuries too, and the only thing the tighter
// number bought was locking out the people who type. The portal auto-submits
// the moment a sixth digit is entered, so a single mistyped digit spends an
// attempt the user never chose to spend — five of those is three real tries.
const (
	mfaFailWindow    = 5 * time.Minute
	mfaFailThreshold = 15
)

// mfaLockDurations escalates the lock with each successive trip. A human who
// mistypes waits a minute; something grinding codes lands on the long lock and
// stays there. A flat 15 minutes is indistinguishable from a broken account and
// buys nothing an escalating one does not.
var mfaLockDurations = []time.Duration{
	1 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
}

// mfaLockLevelTTL is how long the escalation remembers previous trips. Longer
// than the longest lock, so a repeat offender resuming right after a lock
// expires escalates rather than restarting at one minute.
const mfaLockLevelTTL = 1 * time.Hour

// ErrMFARateLimited is returned when the caller has tripped the MFA
// rate-limit and must wait before retrying. RetryAfter is exposed via
// MFARateLimitError so handlers can surface a useful Retry-After header.
// Aliased to pkg/mfaerr so the EE module can branch on it across the
// registry seam and render a 429 instead of "invalid mfa code".
var ErrMFARateLimited = mfaerr.ErrRateLimited

// MFARateLimitError wraps ErrMFARateLimited with how long the lock has
// left. errors.Is(err, ErrMFARateLimited) still works.
type MFARateLimitError struct {
	RetryAfter time.Duration
}

func (e *MFARateLimitError) Error() string {
	return fmt.Sprintf("%s (retry after %s)", ErrMFARateLimited.Error(), e.RetryAfter.Truncate(time.Second))
}

func (e *MFARateLimitError) Is(target error) bool { return target == ErrMFARateLimited }

// RetryAfterDuration satisfies mfaerr.RetryAfterer so handlers outside this
// module (the EE external-IdP MFA verify) can emit a Retry-After header.
func (e *MFARateLimitError) RetryAfterDuration() time.Duration { return e.RetryAfter }

// MFARateLimiter is the public surface security_handler.verifyTOTP and
// engine.VerifyMFAChallenge share. Two counter scopes:
//
//	user → catches "attacker has the right password, tries TOTP codes"
//	ip   → catches "scripted scan against many users from one host"
//
// Either tripping locks both paths for the current escalation step. Success
// on a real code clears both counters and the escalation.
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

// RecordFailure bumps the fail counters; once the threshold is hit it sets a
// lock key that Check sees, for a duration that escalates with each successive
// trip. Counters auto-expire after mfaFailWindow so attacks that pause have to
// start over.
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
			l.lock(ctx, key)
		}
	}
}

// lock trips the lock on one counter key and escalates its duration. The
// counter is deleted along the way: it outlives the short first lock, so
// leaving it at the threshold would re-lock the account on the very next
// keystroke after the lock lifted.
func (l *MFARateLimiter) lock(ctx context.Context, key string) {
	level, err := l.rdb.Incr(ctx, key+":locklevel").Result()
	if err != nil {
		// Can't read the escalation — fail closed on the longest lock rather
		// than handing out the lenient one.
		level = int64(len(mfaLockDurations))
	}
	if level == 1 {
		l.rdb.Expire(ctx, key+":locklevel", mfaLockLevelTTL)
	}
	idx := int(level) - 1
	if idx < 0 || idx >= len(mfaLockDurations) {
		idx = len(mfaLockDurations) - 1
	}
	l.rdb.Set(ctx, key+":locked", "1", mfaLockDurations[idx])
	l.rdb.Del(ctx, key)
}

// Reset clears both counters, the lock and the escalation level — called on a
// successful verification. A correct code is a clean slate: the person proved
// who they are, so the next honest mistake starts at the short lock again.
func (l *MFARateLimiter) Reset(ctx context.Context, userID int64, ip string) {
	if l == nil || l.rdb == nil {
		return
	}
	keys := []string{}
	if k := userKey(userID); k != "" {
		keys = append(keys, k, k+":locked", k+":locklevel")
	}
	if k := ipKey(ip); k != "" {
		keys = append(keys, k, k+":locked", k+":locklevel")
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

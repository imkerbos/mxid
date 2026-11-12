// Package ratelimit provides a reusable Redis-backed brute-force limiter
// keyed by (purpose, identifier). It generalizes the hand-rolled MFA
// limiter in internal/domain/authn so the same lock-on-failure behaviour
// can back login (per-IP + per-user), sms-otp, magic-link and
// password-reset flows.
//
// The model is "fail counter + auto-expiring lock", NOT a token bucket:
//
//	RecordFailure bumps a per-key counter that expires after Window.
//	Once the counter reaches MaxAttempts a separate ":locked" key is set
//	with Lockout TTL. Check reports the lock (with RetryAfter) until that
//	TTL elapses — Redis expiry releases the lock automatically, so a
//	crashed/forgotten Reset never strands a caller.
//	Reset clears both the counter and the lock on a successful attempt.
//
// Keys are namespaced "mxid:rl:<purpose>:<identifier>" so distinct
// purposes and identifiers never collide.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// recordScript atomically increments the failure counter, arms its window
// expiry on the first failure, and — once MaxAttempts is reached — sets the
// auto-expiring lock (NX, so a running lock's TTL is never extended). It
// returns the lock's remaining TTL in milliseconds (>0 = locked) or 0. Doing
// the increment-and-lock in one round-trip closes the check-then-act race that
// would otherwise let concurrent requests slip past MaxAttempts.
//
// KEYS[1]=counter, KEYS[2]=lock. ARGV[1]=window ms, ARGV[2]=maxAttempts,
// ARGV[3]=lockout ms.
var recordScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if c >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[3])
  return redis.call('PTTL', KEYS[2])
end
return 0
`)

// countScript increments the failure counter and arms its window expiry on the
// first failure, WITHOUT ever setting the lock key. It backs
// RecordFailureCount, for a dimension that is counted but must never become a
// binary lock. Returns the post-increment count.
//
// KEYS[1]=counter. ARGV[1]=window ms.
var countScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

// keyPrefix namespaces every key this package writes. Kept distinct from
// the middleware's "rl:" fixed-window keys so the two limiters never alias.
const keyPrefix = "mxid:rl"

// ErrRateLimited is the sentinel returned (wrapped in *RateLimitError)
// when a key is locked. Callers can match with errors.Is.
var ErrRateLimited = errors.New("rate limited: too many attempts, temporarily locked")

// RateLimitError reports that the (purpose, identifier) is currently
// locked. RetryAfter is the remaining lock TTL so handlers can surface a
// Retry-After header. errors.Is(err, ErrRateLimited) still matches.
type RateLimitError struct {
	Purpose    string
	Identifier string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s [%s/%s] (retry after %s)",
		ErrRateLimited.Error(), e.Purpose, e.Identifier, e.RetryAfter.Truncate(time.Second))
}

func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// Config tunes one limiter. Zero values are replaced with safe defaults
// at construction (see New), so a partially-filled Config is still usable.
type Config struct {
	// Purpose namespaces the limiter, e.g. "sms_login", "password".
	// Required — New returns an error when empty.
	Purpose string
	// MaxAttempts is the number of failures within Window that trips the
	// lock. Must be >= 1.
	MaxAttempts int
	// Window is how long the failure counter lives. A caller that pauses
	// longer than Window starts counting from zero again.
	Window time.Duration
	// Lockout is the TTL of the lock once MaxAttempts is reached. This is
	// the value reported as RetryAfter while locked.
	Lockout time.Duration
	// FailOpen controls behaviour when the Redis store errors. Default
	// (false) is fail-CLOSED: a store outage conservatively treats the
	// attempt as locked, so the brute-force control never silently
	// disappears under load/attack. Set true only for low-value flows where
	// availability outweighs the protection. (IAM auth already depends on
	// Redis for sessions, so fail-closed here adds no new hard dependency.)
	FailOpen bool
}

const (
	defaultMaxAttempts = 5
	defaultWindow      = 5 * time.Minute
	defaultLockout     = 15 * time.Minute
)

func (c Config) withDefaults() Config {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultMaxAttempts
	}
	if c.Window <= 0 {
		c.Window = defaultWindow
	}
	if c.Lockout <= 0 {
		c.Lockout = defaultLockout
	}
	return c
}

// Limiter is a Redis-backed brute-force limiter for a single Purpose.
// One Limiter typically handles many identifiers (per-IP, per-user, per
// phone number). It is safe for concurrent use — all state lives in Redis.
type Limiter struct {
	rdb *redis.Client
	cfg Config
}

// New builds a Limiter. It returns an error when rdb is nil or
// cfg.Purpose is empty; all other zero fields fall back to package
// defaults.
func New(rdb *redis.Client, cfg Config) (*Limiter, error) {
	if rdb == nil {
		return nil, errors.New("ratelimit: redis client is nil")
	}
	if cfg.Purpose == "" {
		return nil, errors.New("ratelimit: Config.Purpose is required")
	}
	return &Limiter{rdb: rdb, cfg: cfg.withDefaults()}, nil
}

// Config returns the effective (defaults-applied) configuration. Useful
// for tests and for handlers that want to echo limits to clients.
func (l *Limiter) Config() Config { return l.cfg }

// counterKey is the failure-counter key for one identifier. The identifier is
// SHA-256 hashed before it touches the key so a value containing the ":"
// delimiter (or the ":locked" suffix) cannot span the keyspace and collide
// with another scope's key — e.g. an attacker logging in as username
// "ip:1.2.3.4" or "victim:locked" cannot poison/lock another scope's key.
// Purpose comes from server code (trusted) and stays readable for ops.
func (l *Limiter) counterKey(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return fmt.Sprintf("%s:%s:%s", keyPrefix, l.cfg.Purpose, hex.EncodeToString(sum[:]))
}

// lockKey is the auto-expiring lock key for one identifier.
func (l *Limiter) lockKey(identifier string) string {
	return l.counterKey(identifier) + ":locked"
}

// cooldownKey is the short self-expiring "refuse for now" window key for one
// identifier. Kept apart from lockKey because it is a different control: a
// cooldown is armed for a caller-chosen duration and is NOT reported as a
// *RateLimitError, so a caller can refuse an attempt without the refusal being
// distinguishable from an ordinary failure.
func (l *Limiter) cooldownKey(identifier string) string {
	return l.counterKey(identifier) + ":cooldown"
}

// failResult is returned on a Redis store error: nil when FailOpen, otherwise a
// conservative lock (fail-closed) so the brute-force control holds during an
// outage instead of silently admitting unlimited attempts.
func (l *Limiter) failResult(identifier string) error {
	if l.cfg.FailOpen {
		return nil
	}
	return &RateLimitError{
		Purpose:    l.cfg.Purpose,
		Identifier: identifier,
		RetryAfter: l.cfg.Lockout,
	}
}

// Check returns nil when the identifier may proceed, or a *RateLimitError
// (matching ErrRateLimited) carrying RetryAfter when locked. A nil
// Limiter is treated as "no limit" so optional wiring stays ergonomic.
// On a Redis store error the result follows Config.FailOpen — fail-closed
// by default, so the control holds during an outage.
func (l *Limiter) Check(ctx context.Context, identifier string) error {
	if l == nil || l.rdb == nil || identifier == "" {
		return nil
	}
	ttl, err := l.rdb.TTL(ctx, l.lockKey(identifier)).Result()
	if err != nil && err != redis.Nil {
		// Real store error — fail per policy (closed by default).
		return l.failResult(identifier)
	}
	if ttl > 0 {
		return &RateLimitError{
			Purpose:    l.cfg.Purpose,
			Identifier: identifier,
			RetryAfter: ttl,
		}
	}
	return nil
}

// RecordFailure increments the failure counter for the identifier and,
// once it reaches MaxAttempts, sets the lock for Lockout. The counter
// itself expires after Window, so spaced-out attempts never accumulate
// into a lock. Returns the resulting *RateLimitError if this call tripped
// (or the caller is already inside) a lock, else nil — letting callers
// surface RetryAfter immediately without a follow-up Check.
func (l *Limiter) RecordFailure(ctx context.Context, identifier string) error {
	if l == nil || l.rdb == nil || identifier == "" {
		return nil
	}
	keys := []string{l.counterKey(identifier), l.lockKey(identifier)}
	argv := []any{
		l.cfg.Window.Milliseconds(),
		l.cfg.MaxAttempts,
		l.cfg.Lockout.Milliseconds(),
	}
	lockTTLMs, err := recordScript.Run(ctx, l.rdb, keys, argv...).Int64()
	if err != nil {
		// Real store error — fail per policy (closed by default).
		return l.failResult(identifier)
	}
	if lockTTLMs > 0 {
		return &RateLimitError{
			Purpose:    l.cfg.Purpose,
			Identifier: identifier,
			RetryAfter: time.Duration(lockTTLMs) * time.Millisecond,
		}
	}
	return nil
}

// RecordFailureCount increments the failure counter for the identifier and
// returns the resulting count. Unlike RecordFailure it NEVER arms the lock, so
// the identifier can be counted without ever becoming lockable. Use it for a
// dimension where a binary lock would be a denial of service — a per-account
// login dimension, where anyone who knows a username could otherwise lock its
// owner out. Returns 0 on a store error (the caller cannot distinguish an
// outage from a first failure, which is the conservative reading for a control
// that only throttles).
func (l *Limiter) RecordFailureCount(ctx context.Context, identifier string) int {
	if l == nil || l.rdb == nil || identifier == "" {
		return 0
	}
	n, err := countScript.Run(ctx, l.rdb,
		[]string{l.counterKey(identifier)}, l.cfg.Window.Milliseconds()).Int()
	if err != nil {
		return 0
	}
	return n
}

// ArmCooldown starts (or restarts) a cooldown window of d on the identifier.
// InCooldown reports it until the TTL elapses; Redis expiry releases it, so a
// missed Reset never strands the caller. A non-positive d is a no-op.
func (l *Limiter) ArmCooldown(ctx context.Context, identifier string, d time.Duration) {
	if l == nil || l.rdb == nil || identifier == "" || d <= 0 {
		return
	}
	l.rdb.Set(ctx, l.cooldownKey(identifier), "1", d)
}

// InCooldown reports whether a cooldown window is currently armed on the
// identifier.
//
// A store error reports false, NOT true: this control refuses attempts, so
// failing it closed would turn a Redis outage into "every login is refused".
// The callers that must fail closed on an outage (Check / RecordFailure) still
// do, and in the login flow they run first.
func (l *Limiter) InCooldown(ctx context.Context, identifier string) bool {
	if l == nil || l.rdb == nil || identifier == "" {
		return false
	}
	n, err := l.rdb.Exists(ctx, l.cooldownKey(identifier)).Result()
	return err == nil && n > 0
}

// Reset clears the failure counter, lock and cooldown for the identifier —
// call on a successful attempt so a legitimate user isn't penalised for earlier
// typos.
func (l *Limiter) Reset(ctx context.Context, identifier string) {
	if l == nil || l.rdb == nil || identifier == "" {
		return
	}
	l.rdb.Del(ctx, l.counterKey(identifier), l.lockKey(identifier), l.cooldownKey(identifier))
}

// FailureCount returns the current failure count recorded for the identifier
// (0 when none, expired, or on a store error). It's a read-only peek used by
// callers that gate behaviour on the running tally — e.g. demanding a captcha
// only after N failures — without recording a new failure. A nil Limiter or
// empty identifier returns 0.
func (l *Limiter) FailureCount(ctx context.Context, identifier string) int {
	if l == nil || l.rdb == nil || identifier == "" {
		return 0
	}
	n, err := l.rdb.Get(ctx, l.counterKey(identifier)).Int()
	if err != nil {
		return 0
	}
	return n
}

// CheckMany applies Check to every identifier and returns the first lock
// encountered (the most restrictive view: if any scope is locked, the
// attempt is blocked). Empty identifiers are skipped. This is the
// convenience the login flow wants — pass both "ip:..." and "user:...".
func (l *Limiter) CheckMany(ctx context.Context, identifiers ...string) error {
	if l == nil || l.rdb == nil {
		return nil
	}
	for _, id := range identifiers {
		if id == "" {
			continue
		}
		if err := l.Check(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// RecordFailureMany records a failure against every identifier and
// returns the first lock that resulted. Use alongside CheckMany when every
// dimension of a flow is lockable; a dimension that must be counted but never
// locked takes RecordFailureCount instead.
func (l *Limiter) RecordFailureMany(ctx context.Context, identifiers ...string) error {
	if l == nil || l.rdb == nil {
		return nil
	}
	var blocked error
	for _, id := range identifiers {
		if id == "" {
			continue
		}
		if err := l.RecordFailure(ctx, id); err != nil && blocked == nil {
			blocked = err
		}
	}
	return blocked
}

// ResetMany clears every identifier — the success-path mirror of
// RecordFailureMany.
func (l *Limiter) ResetMany(ctx context.Context, identifiers ...string) {
	if l == nil || l.rdb == nil {
		return
	}
	for _, id := range identifiers {
		l.Reset(ctx, id)
	}
}

package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestLimiter(t *testing.T, cfg Config) (*Limiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	l, err := New(rdb, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, mr
}

func TestNew_Validation(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cases := []struct {
		name    string
		rdb     *redis.Client
		cfg     Config
		wantErr bool
	}{
		{"nil redis", nil, Config{Purpose: "x"}, true},
		{"empty purpose", rdb, Config{Purpose: ""}, true},
		{"ok minimal", rdb, Config{Purpose: "sms_login"}, false},
		{"ok full", rdb, Config{Purpose: "password", MaxAttempts: 3, Window: time.Minute, Lockout: time.Hour}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.rdb, tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_Defaults(t *testing.T) {
	l, _ := newTestLimiter(t, Config{Purpose: "x"})
	got := l.Config()
	if got.MaxAttempts != defaultMaxAttempts {
		t.Errorf("MaxAttempts = %d, want %d", got.MaxAttempts, defaultMaxAttempts)
	}
	if got.Window != defaultWindow {
		t.Errorf("Window = %s, want %s", got.Window, defaultWindow)
	}
	if got.Lockout != defaultLockout {
		t.Errorf("Lockout = %s, want %s", got.Lockout, defaultLockout)
	}
}

func TestCheck_UnderLimitOK(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "sms_login", MaxAttempts: 3, Window: time.Minute, Lockout: 10 * time.Minute}
	l, _ := newTestLimiter(t, cfg)
	id := "+8613800000000"

	// MaxAttempts-1 failures must stay unlocked.
	for i := 0; i < cfg.MaxAttempts-1; i++ {
		if err := l.RecordFailure(ctx, id); err != nil {
			t.Fatalf("RecordFailure %d returned lock prematurely: %v", i, err)
		}
		if err := l.Check(ctx, id); err != nil {
			t.Fatalf("Check after %d failures = %v, want nil", i+1, err)
		}
	}
}

func TestRecordFailure_ExceedBlocksWithRetryAfter(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "password", MaxAttempts: 3, Window: time.Minute, Lockout: 10 * time.Minute}
	l, _ := newTestLimiter(t, cfg)
	id := "ip:1.2.3.4"

	var lockErr error
	for i := 0; i < cfg.MaxAttempts; i++ {
		lockErr = l.RecordFailure(ctx, id)
	}
	// The MaxAttempts-th failure should have returned a lock.
	if lockErr == nil {
		t.Fatal("RecordFailure at threshold returned nil, want lock error")
	}
	if !errors.Is(lockErr, ErrRateLimited) {
		t.Fatalf("returned error not ErrRateLimited: %v", lockErr)
	}
	var rle *RateLimitError
	if !errors.As(lockErr, &rle) {
		t.Fatalf("error not *RateLimitError: %T", lockErr)
	}
	if rle.RetryAfter <= 0 || rle.RetryAfter > cfg.Lockout {
		t.Errorf("RetryAfter = %s, want (0, %s]", rle.RetryAfter, cfg.Lockout)
	}
	if rle.Purpose != cfg.Purpose || rle.Identifier != id {
		t.Errorf("error meta = %s/%s, want %s/%s", rle.Purpose, rle.Identifier, cfg.Purpose, id)
	}

	// Subsequent Check must also report the lock.
	if err := l.Check(ctx, id); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Check after lock = %v, want ErrRateLimited", err)
	}
}

func TestLockout_Expiry(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "magic_link", MaxAttempts: 2, Window: time.Minute, Lockout: 30 * time.Second}
	l, mr := newTestLimiter(t, cfg)
	id := "user:42"

	for i := 0; i < cfg.MaxAttempts; i++ {
		l.RecordFailure(ctx, id)
	}
	if err := l.Check(ctx, id); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Check while locked = %v, want ErrRateLimited", err)
	}

	// Advance miniredis past the lock TTL — Redis auto-expiry releases it.
	mr.FastForward(cfg.Lockout + time.Second)

	if err := l.Check(ctx, id); err != nil {
		t.Fatalf("Check after lock expiry = %v, want nil", err)
	}
}

func TestCounter_WindowExpiry(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "password", MaxAttempts: 3, Window: 30 * time.Second, Lockout: 10 * time.Minute}
	l, mr := newTestLimiter(t, cfg)
	id := "ip:9.9.9.9"

	// Two failures, then let the counter window expire.
	l.RecordFailure(ctx, id)
	l.RecordFailure(ctx, id)
	mr.FastForward(cfg.Window + time.Second)

	// Counter reset to zero: two more failures still must not lock
	// (threshold is 3, and the earlier two expired).
	if err := l.RecordFailure(ctx, id); err != nil {
		t.Fatalf("RecordFailure after window expiry locked early: %v", err)
	}
	if err := l.Check(ctx, id); err != nil {
		t.Fatalf("Check = %v, want nil (counter should have reset)", err)
	}
}

func TestReset_ClearsCounterAndLock(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "sms_login", MaxAttempts: 2, Window: time.Minute, Lockout: 10 * time.Minute}
	l, _ := newTestLimiter(t, cfg)
	id := "+8613900000000"

	for i := 0; i < cfg.MaxAttempts; i++ {
		l.RecordFailure(ctx, id)
	}
	if err := l.Check(ctx, id); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("precondition: expected lock, got %v", err)
	}

	l.Reset(ctx, id)

	if err := l.Check(ctx, id); err != nil {
		t.Fatalf("Check after Reset = %v, want nil", err)
	}
	// Counter must also be cleared: a fresh failure must not immediately
	// re-lock (would only happen if the old counter survived).
	if err := l.RecordFailure(ctx, id); err != nil {
		t.Fatalf("RecordFailure after Reset re-locked early: %v", err)
	}
}

func TestPerKeyIsolation(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "password", MaxAttempts: 2, Window: time.Minute, Lockout: 10 * time.Minute}
	l, _ := newTestLimiter(t, cfg)

	// Lock identifier A.
	for i := 0; i < cfg.MaxAttempts; i++ {
		l.RecordFailure(ctx, "ip:1.1.1.1")
	}
	if err := l.Check(ctx, "ip:1.1.1.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("A should be locked, got %v", err)
	}
	// B is untouched.
	if err := l.Check(ctx, "ip:2.2.2.2"); err != nil {
		t.Fatalf("B should be free, got %v", err)
	}
}

func TestPurposeIsolation(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	a, err := New(rdb, Config{Purpose: "sms_login", MaxAttempts: 2, Window: time.Minute, Lockout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(rdb, Config{Purpose: "password", MaxAttempts: 2, Window: time.Minute, Lockout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	id := "ip:3.3.3.3" // same identifier, different purpose
	for i := 0; i < 2; i++ {
		a.RecordFailure(ctx, id)
	}
	if err := a.Check(ctx, id); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("purpose A should be locked, got %v", err)
	}
	if err := b.Check(ctx, id); err != nil {
		t.Fatalf("purpose B (same identifier) should be free, got %v", err)
	}
}

func TestEmptyIdentifierNoop(t *testing.T) {
	ctx := context.Background()
	l, _ := newTestLimiter(t, Config{Purpose: "x", MaxAttempts: 1, Window: time.Minute, Lockout: time.Minute})
	if err := l.Check(ctx, ""); err != nil {
		t.Errorf("Check(\"\") = %v, want nil", err)
	}
	if err := l.RecordFailure(ctx, ""); err != nil {
		t.Errorf("RecordFailure(\"\") = %v, want nil", err)
	}
	l.Reset(ctx, "") // must not panic
}

func TestNilLimiterSafe(t *testing.T) {
	ctx := context.Background()
	var l *Limiter
	if err := l.Check(ctx, "x"); err != nil {
		t.Errorf("nil Check = %v, want nil", err)
	}
	if err := l.RecordFailure(ctx, "x"); err != nil {
		t.Errorf("nil RecordFailure = %v, want nil", err)
	}
	l.Reset(ctx, "x")
	if err := l.CheckMany(ctx, "x", "y"); err != nil {
		t.Errorf("nil CheckMany = %v, want nil", err)
	}
	if err := l.RecordFailureMany(ctx, "x"); err != nil {
		t.Errorf("nil RecordFailureMany = %v, want nil", err)
	}
	l.ResetMany(ctx, "x")
}

func TestMany_LoginScopes(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "login", MaxAttempts: 3, Window: time.Minute, Lockout: 10 * time.Minute}
	l, _ := newTestLimiter(t, cfg)

	ip, user := "ip:5.5.5.5", "user:7"

	// Drive the user scope to its lock while the IP scope only sees the
	// same number of failures (also locking). Verify CheckMany surfaces it.
	for i := 0; i < cfg.MaxAttempts; i++ {
		l.RecordFailureMany(ctx, ip, user)
	}
	if err := l.CheckMany(ctx, ip, user); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("CheckMany after threshold = %v, want ErrRateLimited", err)
	}

	// A successful login resets both scopes.
	l.ResetMany(ctx, ip, user)
	if err := l.CheckMany(ctx, ip, user); err != nil {
		t.Fatalf("CheckMany after ResetMany = %v, want nil", err)
	}
}

func TestMany_OneScopeLocksBlocks(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "login", MaxAttempts: 2, Window: time.Minute, Lockout: 10 * time.Minute}
	l, _ := newTestLimiter(t, cfg)

	ip, user := "ip:6.6.6.6", "user:8"
	// Only the user scope trips.
	l.RecordFailure(ctx, user)
	l.RecordFailure(ctx, user)

	if err := l.CheckMany(ctx, ip, user); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("CheckMany with one locked scope = %v, want ErrRateLimited", err)
	}
	// The IP scope on its own is still free.
	if err := l.Check(ctx, ip); err != nil {
		t.Fatalf("ip scope = %v, want nil", err)
	}
}

func TestLockTTLNotExtendedByLaterFailures(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Purpose: "password", MaxAttempts: 2, Window: 10 * time.Minute, Lockout: 60 * time.Second}
	l, mr := newTestLimiter(t, cfg)
	id := "ip:7.7.7.7"

	l.RecordFailure(ctx, id)
	l.RecordFailure(ctx, id) // locks for 60s

	mr.FastForward(40 * time.Second) // 20s of lock remain
	l.RecordFailure(ctx, id)         // must NOT reset the 60s TTL (SetNX)

	mr.FastForward(21 * time.Second) // original lock would now be expired
	if err := l.Check(ctx, id); err != nil {
		t.Fatalf("lock TTL was extended by later failure: Check = %v, want nil", err)
	}
}

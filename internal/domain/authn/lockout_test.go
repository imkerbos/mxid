package authn

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/ratelimit"
)

// statusSpyRepo records UpdateStatus calls so the test can prove the
// brute-force auto-lock path no longer flips mxid_user.status (that remains
// admin-only).
type statusSpyRepo struct {
	statusCalls int
}

func (r *statusSpyRepo) GetByID(_ context.Context, id int64) (*UserInfo, error) {
	return &UserInfo{ID: id, Status: statusActive}, nil
}
func (r *statusSpyRepo) UpdateLastLogin(_ context.Context, _ int64, _ string) error { return nil }
func (r *statusSpyRepo) UpdateStatus(_ context.Context, _ int64, _ int) error {
	r.statusCalls++
	return nil
}

func newLockoutEngine(t *testing.T) (*Engine, *statusSpyRepo, *miniredis.Miniredis, int) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	repo := &statusSpyRepo{}
	const maxAttempts = 3
	const lockout = 15 * time.Minute
	e := &Engine{
		eventBus:    event.NewBus(zap.NewNop()),
		userRepo:    repo,
		rdb:         rdb,
		loginConfig: &bootstrap.LoginConfig{MaxFailedAttempts: maxAttempts, LockoutDuration: lockout},
	}
	lim, err := ratelimit.New(rdb, ratelimit.Config{
		Purpose: "login", MaxAttempts: maxAttempts, Window: lockout, Lockout: lockout,
	})
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	e.SetLoginLimiter(lim)
	return e, repo, mr, maxAttempts
}

// Brute force trips a Redis TTL lock (not a DB status flip) and the lock
// auto-expires when its TTL elapses.
func TestBruteForceLock_TripsAndAutoExpires(t *testing.T) {
	e, repo, mr, maxAttempts := newLockoutEngine(t)
	ctx := context.Background()
	const userID = int64(7)
	req := &AuthRequest{TenantID: 1, ClientIP: "10.0.0.9"}

	// Before any failure, not locked.
	if err := e.checkLoginLock(ctx, userID, req.ClientIP); err != nil {
		t.Fatalf("unexpected pre-lock: %v", err)
	}

	for i := 0; i < maxAttempts; i++ {
		e.trackFailure(ctx, userID, req)
	}

	// Now locked (per-user OR per-IP both tripped).
	if err := e.checkLoginLock(ctx, userID, req.ClientIP); err == nil {
		t.Fatal("after threshold the brute-force lock must trip, got nil")
	}

	// Critically: status was NEVER flipped — auto-lock is Redis-only now.
	if repo.statusCalls != 0 {
		t.Fatalf("brute-force auto-lock must NOT call UpdateStatus, got %d calls", repo.statusCalls)
	}

	// Advance past the lock TTL: Redis expiry self-heals the lock.
	mr.FastForward(16 * time.Minute)
	if err := e.checkLoginLock(ctx, userID, req.ClientIP); err != nil {
		t.Fatalf("lock must auto-expire after TTL, still locked: %v", err)
	}
}

// The per-IP dimension locks even a different user from the same IP — a
// scripted scan across usernames from one host is throttled.
func TestBruteForceLock_PerIPDimension(t *testing.T) {
	e, _, _, maxAttempts := newLockoutEngine(t)
	ctx := context.Background()
	ip := "203.0.113.5"

	// Spread failures across DIFFERENT users but the same IP.
	for i := 0; i < maxAttempts; i++ {
		e.trackFailure(ctx, int64(1000+i), &AuthRequest{TenantID: 1, ClientIP: ip})
	}

	// A brand-new user from that IP is blocked by the per-IP lock (pre-auth
	// IP-only check, userID=0).
	if err := e.checkLoginLock(ctx, 0, ip); err == nil {
		t.Fatal("per-IP lock must block further attempts from the same IP, got nil")
	}
}

// Admin lock stays separate: a successful reset of the brute-force counters
// does NOT touch DB status, and the admin-set status=Locked is independent of
// the Redis lock.
func TestBruteForceLock_AdminLockIsSeparate(t *testing.T) {
	e, repo, _, maxAttempts := newLockoutEngine(t)
	ctx := context.Background()
	const userID = int64(8)
	req := &AuthRequest{TenantID: 1, ClientIP: "10.0.0.10"}

	for i := 0; i < maxAttempts; i++ {
		e.trackFailure(ctx, userID, req)
	}
	// A successful login clears the brute-force budget without ever calling
	// UpdateStatus (the admin lock path is the only DB-status writer).
	e.clearFailureCountIP(ctx, userID, req.ClientIP)
	if err := e.checkLoginLock(ctx, userID, req.ClientIP); err != nil {
		t.Fatalf("after reset the brute-force lock must clear, still locked: %v", err)
	}
	if repo.statusCalls != 0 {
		t.Fatalf("neither lock nor reset may call UpdateStatus, got %d", repo.statusCalls)
	}
}

// With NO limiter wired (legacy fallback), trackFailure still must not flip
// mxid_user.status — the permanent auto-lock was the defect we removed.
func TestBruteForceLock_LegacyFallbackNoStatusFlip(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	repo := &statusSpyRepo{}
	e := &Engine{
		eventBus:    event.NewBus(zap.NewNop()),
		userRepo:    repo,
		rdb:         rdb,
		loginConfig: &bootstrap.LoginConfig{MaxFailedAttempts: 2, LockoutDuration: time.Minute},
	}
	// No SetLoginLimiter -> legacy path.
	ctx := context.Background()
	req := &AuthRequest{TenantID: 1, ClientIP: "1.2.3.4"}
	for i := 0; i < 5; i++ {
		e.trackFailure(ctx, 9, req)
	}
	if repo.statusCalls != 0 {
		t.Fatalf("legacy fallback must not flip status, got %d calls", repo.statusCalls)
	}
}

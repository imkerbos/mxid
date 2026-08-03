package authn

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
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

// unknownUserProvider is what the local provider does for a username that
// resolves to nobody: a uniform AuthFailed with no UserID.
type unknownUserProvider struct{}

func (unknownUserProvider) Type() string { return "local" }
func (unknownUserProvider) Authenticate(_ context.Context, _ *AuthRequest) (*AuthResult, error) {
	return &AuthResult{Status: AuthFailed}, nil
}

// A login attempt against a username that matches no account still has to move
// the per-IP counter.
//
// It did not: Login skipped trackFailure entirely whenever the provider
// returned UserID 0, which is exactly what an unknown username returns. Both
// dimensions were skipped with it, so a scripted scan over invented usernames
// incremented nothing — no captcha was ever demanded (the threshold reads the
// per-IP count) and no IP lock ever tripped, however many attempts it made. The
// comment on trackFailure claimed the per-IP dimension "throttles a scripted
// scan"; that was the one case where it did not.
//
// Driven through Login, not trackFailure: the guard being removed lived at the
// call site, so a test that called trackFailure directly passed against the
// broken version too. It did, on the first attempt.
func TestFailedLoginForAnUnknownUserStillCountsAgainstTheIP(t *testing.T) {
	e, _, _, maxAttempts := newLockoutEngine(t)
	e.providers = map[string]Provider{"local": unknownUserProvider{}}
	ctx := context.Background()
	const ip = "203.0.113.7"

	if got := e.LoginFailureCount(ctx, ip); got != 0 {
		t.Fatalf("precondition: count = %d, want 0", got)
	}

	for i := 1; i <= maxAttempts; i++ {
		_, err := e.Login(ctx, &AuthRequest{
			AuthType:    "local",
			ClientIP:    ip,
			Credentials: map[string]string{"username": "ghost" + strconv.Itoa(i), "password": "x"},
		}, "portal")
		if err == nil {
			t.Fatalf("attempt %d: login succeeded against the unknown-user provider", i)
		}
		if got := e.LoginFailureCount(ctx, ip); got != i {
			t.Fatalf("after %d unknown-user logins the IP count is %d, want %d — "+
				"username enumeration is unthrottled and the captcha threshold is never reached",
				i, got, i)
		}
	}

	// Having crossed the threshold, the next attempt is refused pre-auth.
	_, err := e.Login(ctx, &AuthRequest{
		AuthType:    "local",
		ClientIP:    ip,
		Credentials: map[string]string{"username": "ghost-final", "password": "x"},
	}, "portal")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked — the IP was not locked after the threshold", err)
	}
}

// An unknown username has no account to lock, so no UserLocked event may claim
// one: a subscriber acting on user_id 0 would be acting on nothing.
func TestUnknownUserLockoutEmitsNoUserLockedEvent(t *testing.T) {
	e, _, _, maxAttempts := newLockoutEngine(t)
	e.providers = map[string]Provider{"local": unknownUserProvider{}}
	ctx := context.Background()

	var locked int32
	e.eventBus.Subscribe(event.UserLocked, func(_ context.Context, _ event.Event) {
		atomic.AddInt32(&locked, 1)
	})

	for i := 0; i < maxAttempts+1; i++ {
		_, _ = e.Login(ctx, &AuthRequest{
			AuthType:    "local",
			ClientIP:    "203.0.113.11",
			Credentials: map[string]string{"username": "ghost", "password": "x"},
		}, "portal")
	}
	// The bus delivers asynchronously.
	time.Sleep(150 * time.Millisecond)
	if n := atomic.LoadInt32(&locked); n != 0 {
		t.Fatalf("UserLocked fired %d times for a username that matches no account", n)
	}
}

package authn

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/session"
)

const (
	backoffUserID   = int64(4242)
	backoffUsername = "alice"
	backoffEmail    = "alice@example.test"
	backoffPassword = "s3cret"
)

// backoffProvider stands in for the local password provider. It resolves the
// identifier the way the real one does (username, then email) and counts how
// often the password was actually evaluated — the observable that says whether
// a refusal happened before the compare or after it.
type backoffProvider struct{ authCalls int }

func (p *backoffProvider) Type() string { return "local" }

func (p *backoffProvider) ResolveAccount(_ context.Context, _ int64, identifier string) (*UserAuth, error) {
	if identifier != backoffUsername && identifier != backoffEmail {
		return nil, errors.New("no such user")
	}
	return &UserAuth{ID: backoffUserID, Username: backoffUsername, Status: statusActive}, nil
}

func (p *backoffProvider) Authenticate(_ context.Context, req *AuthRequest) (*AuthResult, error) {
	p.authCalls++
	id := req.Credentials["username"]
	if id != backoffUsername && id != backoffEmail {
		// Unknown username: no account to key on (mirrors the real provider).
		return &AuthResult{Status: AuthFailed}, nil
	}
	if req.Credentials["password"] != backoffPassword {
		return &AuthResult{UserID: backoffUserID, Username: backoffUsername, Status: AuthFailed}, nil
	}
	return &AuthResult{UserID: backoffUserID, Username: backoffUsername, Status: AuthSuccess}, nil
}

var _ accountResolver = (*backoffProvider)(nil)

// backoffRepo reports whether the account is the platform-seeded break-glass
// admin, which is the server-side state the exemption must read.
type backoffRepo struct{ builtin bool }

func (r backoffRepo) GetByID(_ context.Context, id int64) (*UserInfo, error) {
	return &UserInfo{ID: id, Username: backoffUsername, Status: statusActive, IsBuiltin: r.builtin}, nil
}
func (backoffRepo) UpdateLastLogin(context.Context, int64, string) error { return nil }
func (backoffRepo) UpdateStatus(context.Context, int64, int) error       { return nil }

// backoffSpy captures what the account dimension did: every refusal window
// armed, and every equalizer compare burned on a credential-free refusal.
type backoffSpy struct {
	windows []time.Duration
	burns   int
}

func (s *backoffSpy) armed(_ int64, w time.Duration) { s.windows = append(s.windows, w) }
func (s *backoffSpy) burn(string)                    { s.burns++ }

// newBackoffEngine builds a login engine whose IP dimension can never be what
// blocks an attempt (MaxAttempts far above anything these tests reach), so a
// refusal can only have come from the account dimension.
func newBackoffEngine(t *testing.T, builtin bool) (*Engine, *backoffProvider, *backoffSpy, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	prov := &backoffProvider{}
	e := &Engine{
		providers:   map[string]Provider{"local": prov},
		sessionMgr:  session.NewManager(rdb, time.Hour, 24*time.Hour),
		eventBus:    event.NewBus(zap.NewNop()),
		userRepo:    backoffRepo{builtin: builtin},
		rdb:         rdb,
		loginConfig: &bootstrap.LoginConfig{MaxFailedAttempts: 1000, LockoutDuration: 15 * time.Minute},
	}
	lim, err := ratelimit.New(rdb, ratelimit.Config{
		Purpose: "login", MaxAttempts: 1000, Window: 15 * time.Minute, Lockout: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	e.SetLoginLimiter(lim)
	spy := &backoffSpy{}
	e.accountThrottleArmed = spy.armed
	// Swapped so the refusal's timing equalizer is observable (and free): the
	// real one is a bcrypt compare, and asserting on wall-clock would be flaky.
	e.dummyCompare = spy.burn
	return e, prov, spy, mr
}

// tryLogin attempts a login from the given source IP and returns the error plus
// how long the call took.
func tryLogin(t *testing.T, e *Engine, ip, password string) (error, time.Duration) {
	t.Helper()
	return tryLoginAs(t, e, ip, backoffUsername, password)
}

func tryLoginAs(t *testing.T, e *Engine, ip, identifier, password string) (error, time.Duration) {
	t.Helper()
	start := time.Now()
	_, err := e.Login(context.Background(), &AuthRequest{
		TenantID:    1,
		AuthType:    "local",
		ClientIP:    ip,
		Credentials: map[string]string{"username": identifier, "password": password},
	}, "portal")
	return err, time.Since(start)
}

// rotatingIP yields a distinct source address per attempt: the per-IP dimension
// is untouched by this change, so every test that means to exercise the ACCOUNT
// dimension must make sure no single IP accumulates anything.
func rotatingIP(i int) string { return "198.51.100." + strconv.Itoa(i) }

// failUntilThrottled drives the account to its first armed window and returns
// the attempt count it took.
func failUntilThrottled(t *testing.T, e *Engine, spy *backoffSpy) int {
	t.Helper()
	for i := 1; i <= accountThrottleFreeFailures+1; i++ {
		if err, _ := tryLogin(t, e, rotatingIP(i), "wrong"); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("failure %d: err = %v, want ErrAuthFailed", i, err)
		}
	}
	if len(spy.windows) != 1 {
		t.Fatalf("windows = %v, want exactly one after %d failures",
			spy.windows, accountThrottleFreeFailures+1)
	}
	return accountThrottleFreeFailures + 1
}

// REPRODUCTION. Once an account is being throttled its next attempt must be
// refused WITHOUT the credential being evaluated.
//
// Before the fix this failed: the delay ran after provider.Authenticate had
// already spent the bcrypt compare, so an attacker that does not wait for the
// response kept its full guess rate and the only thing slowed down was our own
// goroutine.
func TestLoginThrottle_ThrottledAttemptDoesNotEvaluateThePassword(t *testing.T) {
	e, prov, spy, _ := newBackoffEngine(t, false)

	n := failUntilThrottled(t, e, spy)
	if prov.authCalls != n {
		t.Fatalf("precondition: provider ran %d times, want %d", prov.authCalls, n)
	}

	err, _ := tryLogin(t, e, rotatingIP(n+1), "wrong")
	if prov.authCalls != n {
		t.Fatalf("a throttled attempt still reached the provider (%d calls, want %d) — the "+
			"password was evaluated and only our own goroutine was slowed down", prov.authCalls, n)
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("throttled attempt: err = %v, want ErrAuthFailed", err)
	}
	// Cheap for us, but not measurably cheap: the refusal pays the same
	// constant-cost compare the unknown-user branch pays, or "fast" would mean
	// "this account is throttled", i.e. "this account exists".
	if spy.burns != 1 {
		t.Fatalf("equalizer compares = %d, want 1 — a refusal that skips it answers "+
			"faster than a real compare and reopens the enumeration oracle", spy.burns)
	}
}

// The reverse case, and the one that matters most: two typos must not cost a
// legitimate user anything at all. The correct password logs in immediately.
func TestLoginThrottle_TwoTyposThenTheRightPasswordLogsInAtOnce(t *testing.T) {
	e, _, spy, _ := newBackoffEngine(t, false)

	for i := 1; i <= 2; i++ {
		if err, _ := tryLogin(t, e, rotatingIP(i), "wrong"); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("typo %d: err = %v, want ErrAuthFailed", i, err)
		}
	}

	err, elapsed := tryLogin(t, e, rotatingIP(3), backoffPassword)
	if err != nil {
		t.Fatalf("the correct password after two typos must log in, got %v", err)
	}
	if len(spy.windows) != 0 {
		t.Fatalf("a user who mistyped twice was throttled (%v) — ordinary typos must be free", spy.windows)
	}
	if spy.burns != 0 {
		t.Fatalf("a legitimate login burned %d equalizer compares — nothing was refused", spy.burns)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("login after two typos took %s, want immediate", elapsed)
	}
}

// Once the window elapses the account is evaluated again — the throttle is a
// throttle, not a lockout the owner has to wait out with an admin.
func TestLoginThrottle_WindowExpiresAndTheOwnerGetsBackIn(t *testing.T) {
	e, prov, spy, mr := newBackoffEngine(t, false)

	n := failUntilThrottled(t, e, spy)
	if err, _ := tryLogin(t, e, rotatingIP(n+1), backoffPassword); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("inside the window even the right password is refused, got %v", err)
	}

	mr.FastForward(accountThrottleMax + time.Second)
	before := prov.authCalls
	if err, _ := tryLogin(t, e, rotatingIP(n+2), backoffPassword); err != nil {
		t.Fatalf("after the window elapsed the correct password must log in, got %v", err)
	}
	if prov.authCalls != before+1 {
		t.Fatalf("provider calls = %d, want %d — the attempt never reached the compare",
			prov.authCalls, before+1)
	}
}

// A throttled account must be indistinguishable from an ordinary wrong
// password: the engine error decides the status code and the business code
// (handleAuthError maps ErrAuthFailed to 401 + NumUnauthenticated, while
// ErrAccountLocked with a limiter cause becomes 429 + NumTooManyAttempts). A
// different response here would be a "this account exists" oracle.
func TestLoginThrottle_RefusalLooksLikeAnOrdinaryFailure(t *testing.T) {
	e, _, spy, _ := newBackoffEngine(t, false)

	first, _ := tryLogin(t, e, rotatingIP(1), "wrong")
	if !errors.Is(first, ErrAuthFailed) {
		t.Fatalf("first failure: err = %v, want ErrAuthFailed", first)
	}
	for i := 2; i <= accountThrottleFreeFailures+1; i++ {
		_, _ = tryLogin(t, e, rotatingIP(i), "wrong")
	}
	if len(spy.windows) == 0 {
		t.Fatal("precondition: no window armed")
	}
	throttled, _ := tryLogin(t, e, rotatingIP(accountThrottleFreeFailures+2), "wrong")

	if !errors.Is(throttled, ErrAuthFailed) {
		t.Fatalf("throttled attempt: err = %v, want ErrAuthFailed", throttled)
	}
	if throttled.Error() != first.Error() {
		t.Fatalf("throttled error %q differs from an ordinary failure %q — the text reaches "+
			"the response body", throttled.Error(), first.Error())
	}
	if errors.Is(throttled, ErrAccountLocked) {
		t.Fatal("a throttled account answered ErrAccountLocked — that is a 429 + " +
			"NumTooManyAttempts, which tells an attacker the account exists and is under attack")
	}
	var rle *ratelimit.RateLimitError
	if errors.As(throttled, &rle) {
		t.Fatalf("throttled attempt carries a RateLimitError (%v) — the handler would surface "+
			"Retry-After and a distinguishable code", rle)
	}
}

// The window escalates and then stops escalating. Each attempt waits out the
// window armed by the previous one, which is the attacker's actual guess rate:
// one evaluated guess per window, with the window doubling under them.
func TestLoginThrottle_EscalatesAndThenCaps(t *testing.T) {
	e, _, spy, mr := newBackoffEngine(t, false)

	for i := 1; i <= 9; i++ {
		if err, _ := tryLogin(t, e, rotatingIP(i), "wrong"); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("failure %d: err = %v, want ErrAuthFailed", i, err)
		}
		// Step past whatever window that failure armed so the next guess is
		// actually evaluated (inside it, nothing is counted).
		mr.FastForward(accountThrottleMax + time.Second)
	}

	want := []time.Duration{
		1 * time.Second, // failure 4
		2 * time.Second, // failure 5
		4 * time.Second, // failure 6
		8 * time.Second, // failure 7
		8 * time.Second, // failure 8 — capped
		8 * time.Second, // failure 9 — capped
	}
	if len(spy.windows) != len(want) {
		t.Fatalf("windows = %v, want %v (the first %d failures must be free)",
			spy.windows, want, accountThrottleFreeFailures)
	}
	for i := range want {
		if spy.windows[i] != want[i] {
			t.Fatalf("windows = %v, want %v", spy.windows, want)
		}
	}
}

// Every attempt above came from a different source address. Spelled out as its
// own assertion because this is the defect: the account dimension was
// write-only, so moving to a fresh IP bought a fresh budget.
func TestLoginThrottle_SourceIPRotationDoesNotResetTheAccountBudget(t *testing.T) {
	e, _, spy, mr := newBackoffEngine(t, false)

	for i := 1; i <= 5; i++ {
		// A brand-new /24 per attempt: nothing the per-IP dimension can hold on to.
		err, _ := tryLoginAs(t, e, "192.0.2."+strconv.Itoa(i*7), backoffUsername, "wrong")
		if !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("failure %d: err = %v, want ErrAuthFailed", i, err)
		}
		mr.FastForward(accountThrottleMax + time.Second)
	}

	if len(spy.windows) != 2 {
		t.Fatalf("windows = %v, want two (failures 4 and 5) — the account budget resets with "+
			"the source IP, so an attacker rotating addresses is never slowed", spy.windows)
	}
}

// An alias for the same account (email instead of username) shares its budget:
// the key is the resolved account, not the string that was typed.
func TestLoginThrottle_AliasIdentifierSharesTheAccountBudget(t *testing.T) {
	e, prov, spy, _ := newBackoffEngine(t, false)

	n := failUntilThrottled(t, e, spy)
	before := prov.authCalls
	if err, _ := tryLoginAs(t, e, rotatingIP(n+1), backoffEmail, "wrong"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("alias attempt: err = %v, want ErrAuthFailed", err)
	}
	if prov.authCalls != before {
		t.Fatalf("switching to the email alias bought a fresh evaluated guess (%d calls, want %d)",
			prov.authCalls, before)
	}
}

// The break-glass account is never throttled. Hard requirement, not a nicety:
// a previous release auto-locked the seeded admin and deadlocked fresh
// deployments, with nobody left who could log in to repair it.
func TestLoginThrottle_BuiltinAdminIsExempt(t *testing.T) {
	e, _, spy, _ := newBackoffEngine(t, true)

	for i := 1; i <= 9; i++ {
		if err, _ := tryLogin(t, e, rotatingIP(i), "wrong"); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("failure %d: err = %v, want ErrAuthFailed", i, err)
		}
	}
	if len(spy.windows) != 0 {
		t.Fatalf("the built-in admin was throttled (%v) — the break-glass account must never be "+
			"refused by an automatic control", spy.windows)
	}

	// And it can still get in, immediately.
	if err, _ := tryLogin(t, e, rotatingIP(10), backoffPassword); err != nil {
		t.Fatalf("built-in admin login after 9 failures: %v", err)
	}
}

// A successful login clears the tally, so the next typo starts from zero again.
func TestLoginThrottle_SuccessClearsTheTally(t *testing.T) {
	e, _, spy, mr := newBackoffEngine(t, false)

	n := failUntilThrottled(t, e, spy)
	mr.FastForward(accountThrottleMax + time.Second)

	if err, _ := tryLogin(t, e, rotatingIP(n+1), backoffPassword); err != nil {
		t.Fatalf("login with the correct password: %v", err)
	}
	spy.windows = nil

	for i := n + 2; i <= n+1+accountThrottleFreeFailures; i++ {
		_, _ = tryLogin(t, e, rotatingIP(i), "wrong")
	}
	if len(spy.windows) != 0 {
		t.Fatalf("after a successful login the account was throttled again at %v — the tally "+
			"did not reset", spy.windows)
	}
}

// The account dimension must never become a binary lock: that would let anyone
// who knows a username lock its owner out, and the limiter's lock answers with
// a distinguishable 429. Asserted on the limiter itself, because the trap is a
// lock KEY existing — once it does, any future reader reopens the hard lock.
func TestLoginThrottle_AccountDimensionNeverArmsALimiterLock(t *testing.T) {
	e, _, _, mr := newBackoffEngine(t, false)
	lim, err := ratelimit.New(e.rdb, ratelimit.Config{
		Purpose: "login", MaxAttempts: 2, Window: time.Minute, Lockout: time.Minute,
	})
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	e.SetLoginLimiter(lim)

	for i := 1; i <= 6; i++ {
		_, _ = tryLogin(t, e, rotatingIP(i), "wrong")
		mr.FastForward(accountThrottleMax + time.Second)
	}

	if err := lim.Check(context.Background(), accountIdentifier(backoffUserID)); err != nil {
		t.Fatalf("the account dimension armed a limiter lock (%v) — anyone who knows a username "+
			"can lock its owner out, and the lock answers 429 with a distinguishable code", err)
	}
}

// Fail-closed is unchanged: with the store unreachable the pre-auth gate still
// refuses rather than admitting unlimited attempts.
func TestLoginThrottle_RedisOutageStillFailsClosed(t *testing.T) {
	e, _, _, mr := newBackoffEngine(t, false)
	mr.Close()

	err, _ := tryLogin(t, e, "203.0.113.1", backoffPassword)
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked — the limiter must stay fail-closed on a store outage", err)
	}
}

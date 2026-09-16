package authn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/mfaerr"
)

// A federated user who fat-fingers a six-digit code was getting locked out for
// a quarter of an hour after five tries, and the portal auto-submits the moment
// the sixth digit lands — so a single typo spent an attempt with no chance to
// proofread. These tests pin the two properties that make the limiter survive a
// real human: a budget that a typing person can live inside, and a first lock
// short enough to wait out rather than escalate to support.

func newTestRateLimiter(t *testing.T) (*MFARateLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewMFARateLimiter(rdb), mr
}

func TestMFARateLimiterThreshold(t *testing.T) {
	l, _ := newTestRateLimiter(t)
	ctx := context.Background()

	for i := 1; i < mfaFailThreshold; i++ {
		l.RecordFailure(ctx, 1, "10.0.0.1")
		if err := l.Check(ctx, 1, "10.0.0.1"); err != nil {
			t.Fatalf("locked after %d failures, threshold is %d: %v", i, mfaFailThreshold, err)
		}
	}
	l.RecordFailure(ctx, 1, "10.0.0.1")
	if err := l.Check(ctx, 1, "10.0.0.1"); err == nil {
		t.Fatalf("not locked after %d failures", mfaFailThreshold)
	}
}

// Fifteen is the budget the portal's auto-submit needs: the FE fires a verify
// the instant a sixth digit is typed, so a mistyped digit costs an attempt the
// user never chose to spend. Pinned as a number because loosening it is a
// security decision that should fail a test, not slip through a refactor.
func TestMFAFailThresholdIsFifteen(t *testing.T) {
	if mfaFailThreshold != 15 {
		t.Fatalf("mfaFailThreshold = %d, want 15", mfaFailThreshold)
	}
}

// The first lock must be short. A fixed fifteen minutes is indistinguishable
// from "my account is broken" and drives a support ticket; a minute is a pause.
// Repeat offenders still escalate to the long lock.
func TestMFARateLimiterLockEscalates(t *testing.T) {
	l, mr := newTestRateLimiter(t)
	ctx := context.Background()

	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, expect := range want {
		for j := 0; j < mfaFailThreshold; j++ {
			l.RecordFailure(ctx, 1, "10.0.0.1")
		}
		err := l.Check(ctx, 1, "10.0.0.1")
		if err == nil {
			t.Fatalf("lock %d: not locked after %d failures", i+1, mfaFailThreshold)
		}
		var rle *MFARateLimitError
		if !errors.As(err, &rle) {
			t.Fatalf("lock %d: error is not *MFARateLimitError: %T", i+1, err)
		}
		if rle.RetryAfter > expect || rle.RetryAfter < expect-time.Second {
			t.Fatalf("lock %d: RetryAfter = %s, want ~%s", i+1, rle.RetryAfter, expect)
		}
		// Wait out this lock so the next round starts unlocked.
		mr.FastForward(expect + time.Second)
	}
}

// Locking must clear the failure counter. Otherwise the counter — which lives
// longer than the first, short lock — is still sitting at the threshold when
// the lock lifts, and the very next typo re-locks instantly.
func TestMFARateLimiterLockClearsCounter(t *testing.T) {
	l, mr := newTestRateLimiter(t)
	ctx := context.Background()

	for i := 0; i < mfaFailThreshold; i++ {
		l.RecordFailure(ctx, 1, "10.0.0.1")
	}
	if err := l.Check(ctx, 1, "10.0.0.1"); err == nil {
		t.Fatal("not locked after reaching the threshold")
	}
	mr.FastForward(time.Minute + time.Second) // first lock is a minute

	l.RecordFailure(ctx, 1, "10.0.0.1")
	if err := l.Check(ctx, 1, "10.0.0.1"); err != nil {
		t.Fatalf("one failure after the lock lifted re-locked the account: %v", err)
	}
}

func TestMFARateLimiterResetClearsEscalation(t *testing.T) {
	l, mr := newTestRateLimiter(t)
	ctx := context.Background()

	for i := 0; i < mfaFailThreshold; i++ {
		l.RecordFailure(ctx, 1, "10.0.0.1")
	}
	mr.FastForward(time.Minute + time.Second)
	// A correct code is a clean slate: the next lock starts at the short
	// duration again, not where the escalation left off.
	l.Reset(ctx, 1, "10.0.0.1")

	for i := 0; i < mfaFailThreshold; i++ {
		l.RecordFailure(ctx, 1, "10.0.0.1")
	}
	err := l.Check(ctx, 1, "10.0.0.1")
	if err == nil {
		t.Fatal("not locked")
	}
	var rle *MFARateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("error is not *MFARateLimitError: %T", err)
	}
	if rle.RetryAfter > time.Minute {
		t.Fatalf("RetryAfter = %s after a reset, want the first-lock duration", rle.RetryAfter)
	}
}

// A replayed code is one the user already proved they held: the digits were
// right, the step was simply already spent. Counting it toward the lockout
// punishes a double-click (and the portal's auto-submit makes double-submits
// routine) while buying nothing — an attacker who can replay a valid code did
// not guess it.
func TestReusedCodeDoesNotCountTowardLockout(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mfa := &stubMFAVerifier{enrolled: true, code: "123456", spent: "654321"}
	e := &Engine{
		eventBus:       event.NewBus(zap.NewNop()),
		rdb:            rdb,
		mfaVerifier:    mfa,
		mfaRateLimiter: NewMFARateLimiter(rdb),
	}
	ctx := context.Background()

	for i := 0; i < mfaFailThreshold*2; i++ {
		err := e.VerifyStepUp(ctx, 1, "10.0.0.1", "654321")
		if !errors.Is(err, ErrMFACodeReused) {
			t.Fatalf("attempt %d: err = %v, want ErrMFACodeReused", i+1, err)
		}
	}
	if err := e.mfaRateLimiter.Check(ctx, 1, "10.0.0.1"); err != nil {
		t.Fatalf("replayed codes locked the account: %v", err)
	}
	// A genuinely wrong code still counts.
	for i := 0; i < mfaFailThreshold; i++ {
		if err := e.VerifyStepUp(ctx, 1, "10.0.0.1", "000000"); !errors.Is(err, ErrMFAVerifyFailed) {
			t.Fatalf("wrong code: err = %v, want ErrMFAVerifyFailed", err)
		}
	}
	if err := e.mfaRateLimiter.Check(ctx, 1, "10.0.0.1"); err == nil {
		t.Fatal("wrong codes did not lock the account")
	}
}

// The EE external-IdP handler consumes VerifyStepUp across a module boundary
// and can only branch on pkg/mfaerr. If the engine's real error stops
// satisfying those sentinels — or stops carrying the remaining lock — that
// handler silently falls back to "invalid mfa code", which is the exact defect
// this work removed. The EE-side test stubs the verifier, so this is the half
// that proves the contract is really produced.
func TestVerifyStepUpErrorsSatisfyTheSeamContract(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	e := &Engine{
		eventBus:       event.NewBus(zap.NewNop()),
		rdb:            rdb,
		mfaVerifier:    &stubMFAVerifier{enrolled: true, code: "123456", spent: "654321"},
		mfaRateLimiter: NewMFARateLimiter(rdb),
	}
	ctx := context.Background()

	if err := e.VerifyStepUp(ctx, 1, "10.0.0.1", "654321"); !errors.Is(err, mfaerr.ErrCodeReused) {
		t.Fatalf("reused code: err = %v, want mfaerr.ErrCodeReused", err)
	}
	if err := e.VerifyStepUp(ctx, 1, "10.0.0.1", "000000"); !errors.Is(err, mfaerr.ErrVerifyFailed) {
		t.Fatalf("wrong code: err = %v, want mfaerr.ErrVerifyFailed", err)
	}

	// Drive it to the lockout the way a person with a drifting phone clock does.
	var locked error
	for i := 0; i < mfaFailThreshold+1; i++ {
		locked = e.VerifyStepUp(ctx, 1, "10.0.0.1", "000000")
	}
	if !errors.Is(locked, mfaerr.ErrRateLimited) {
		t.Fatalf("after %d failures: err = %v, want mfaerr.ErrRateLimited", mfaFailThreshold+1, locked)
	}
	var ra mfaerr.RetryAfterer
	if !errors.As(locked, &ra) {
		t.Fatalf("lockout error does not satisfy mfaerr.RetryAfterer: %T — no Retry-After header possible", locked)
	}
	if d := ra.RetryAfterDuration(); d <= 0 || d > time.Minute {
		t.Fatalf("RetryAfterDuration = %s, want the first-lock duration", d)
	}

	// The CORRECT code is refused while the lock holds — this is precisely what
	// the user experienced as "it just keeps saying my code is wrong".
	if err := e.VerifyStepUp(ctx, 1, "10.0.0.1", "123456"); !errors.Is(err, mfaerr.ErrRateLimited) {
		t.Fatalf("locked, correct code: err = %v, want mfaerr.ErrRateLimited", err)
	}

	// Wait out the short first lock; the right code then works and clears state.
	mr.FastForward(time.Minute + time.Second)
	if err := e.VerifyStepUp(ctx, 1, "10.0.0.1", "123456"); err != nil {
		t.Fatalf("after the lock lifted, the correct code was refused: %v", err)
	}
}

package authn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/ratelimit"
)

func newCaptchaService(t *testing.T) (*CaptchaService, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewCaptchaService(rdb), mr
}

// A store miss must never compare equal to anything. base64Captcha's own
// Captcha.Verify trims both sides, so a blank answer matched a missing entry
// and bypassed the captcha entirely.
func TestCaptchaVerifyRejectsBlankAnswerOnStoreMiss(t *testing.T) {
	svc, _ := newCaptchaService(t)

	for _, answer := range []string{" ", "", "\t\n", "   \t ", "12345"} {
		if svc.Verify("no-such-captcha-id", answer) {
			t.Fatalf("Verify(unknown id, %q) = true, want false", answer)
		}
	}
}

// A blank answer must be rejected even when a real captcha is outstanding.
func TestCaptchaVerifyRejectsBlankAnswerWithLiveCaptcha(t *testing.T) {
	svc, mr := newCaptchaService(t)

	resp, err := svc.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, answer := range []string{" ", "", "\t\n"} {
		if svc.Verify(resp.CaptchaID, answer) {
			t.Fatalf("Verify(live id, %q) = true, want false", answer)
		}
	}
	// A blank attempt must not have consumed the entry either.
	if _, err := mr.Get(captchaKeyPrefix + resp.CaptchaID); err != nil {
		t.Fatalf("captcha entry gone after blank attempt: %v", err)
	}
}

func TestCaptchaVerifyHappyPathIsSingleUse(t *testing.T) {
	svc, mr := newCaptchaService(t)

	resp, err := svc.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer, err := mr.Get(captchaKeyPrefix + resp.CaptchaID)
	if err != nil {
		t.Fatalf("stored captcha answer missing: %v", err)
	}
	if !svc.Verify(resp.CaptchaID, answer) {
		t.Fatalf("Verify(id, correct answer) = false, want true")
	}
	if svc.Verify(resp.CaptchaID, answer) {
		t.Fatalf("Verify replayed the same captcha id, want single use")
	}
}

func TestCaptchaVerifyWrongAnswerIsConsumed(t *testing.T) {
	svc, mr := newCaptchaService(t)

	resp, err := svc.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer, err := mr.Get(captchaKeyPrefix + resp.CaptchaID)
	if err != nil {
		t.Fatalf("stored captcha answer missing: %v", err)
	}
	if svc.Verify(resp.CaptchaID, "00000"+answer) {
		t.Fatalf("Verify(id, wrong answer) = true, want false")
	}
	// A wrong guess burns the captcha, so it cannot be brute-forced.
	if _, err := mr.Get(captchaKeyPrefix + resp.CaptchaID); err == nil {
		t.Fatalf("captcha entry survived a wrong answer, want single use")
	}
	if svc.Verify(resp.CaptchaID, answer) {
		t.Fatalf("Verify succeeded after a wrong answer burned the captcha")
	}
}

// Answers are compared case-insensitively: a warped mixed-case glyph is not
// something a human should have to reproduce exactly.
func TestCaptchaVerifyIsCaseInsensitive(t *testing.T) {
	for _, transform := range []struct {
		name string
		fn   func(string) string
	}{
		{"lowercased", strings.ToLower},
		{"uppercased", strings.ToUpper},
		{"as issued", func(s string) string { return s }},
		{"padded", func(s string) string { return "  " + strings.ToLower(s) + " \t" }},
	} {
		t.Run(transform.name, func(t *testing.T) {
			svc, mr := newCaptchaService(t)
			resp, err := svc.Generate()
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			answer, err := mr.Get(captchaKeyPrefix + resp.CaptchaID)
			if err != nil {
				t.Fatalf("stored captcha answer missing: %v", err)
			}
			if !svc.Verify(resp.CaptchaID, transform.fn(answer)) {
				t.Fatalf("Verify(id, %s answer) = false, want true", transform.name)
			}
		})
	}
}

// The answer must keep its declared length and stay inside the confusable-free
// charset. The sweep also pins the CSPRNG index mapping: every glyph has to be
// reachable, so a truncated modulus or an off-by-one that starves the tail of
// the charset fails here. (No uniqueness assertion — over a 22^6 space a
// collision is legitimate, if improbable, and a flaky guard is worse than none.)
func TestCaptchaAnswerShapeMatchesCharset(t *testing.T) {
	svc, mr := newCaptchaService(t)
	seen := map[rune]bool{}

	for i := 0; i < 200; i++ {
		resp, err := svc.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		answer, err := mr.Get(captchaKeyPrefix + resp.CaptchaID)
		if err != nil {
			t.Fatalf("stored captcha answer missing: %v", err)
		}
		if len(answer) != captchaLength {
			t.Fatalf("answer %q has length %d, want %d", answer, len(answer), captchaLength)
		}
		for _, r := range answer {
			if !strings.ContainsRune(captchaCharset, r) {
				t.Fatalf("answer %q contains %q, outside the charset", answer, r)
			}
			seen[r] = true
		}
	}
	for _, r := range captchaCharset {
		if !seen[r] {
			t.Fatalf("glyph %q never drawn — the charset is not fully reachable", r)
		}
	}
}

// Issuance is budgeted per client so an attacker cannot stockpile captchas to
// pre-solve offline. Generate() itself stays unlimited by design.
func TestCaptchaGenerateForIsRateLimitedPerClient(t *testing.T) {
	svc, _ := newCaptchaService(t)
	ctx := context.Background()

	for i := 0; i < captchaIssueLimit.MaxAttempts; i++ {
		if _, err := svc.GenerateFor(ctx, "198.51.100.7"); err != nil {
			t.Fatalf("GenerateFor attempt %d: unexpected error %v", i+1, err)
		}
	}
	_, err := svc.GenerateFor(ctx, "198.51.100.7")
	if !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("GenerateFor past the budget: err = %v, want ErrRateLimited", err)
	}
	var rlErr *ratelimit.RateLimitError
	if !errors.As(err, &rlErr) || rlErr.RetryAfter <= 0 {
		t.Fatalf("GenerateFor error carries no RetryAfter: %v", err)
	}
	// A different client has its own budget.
	if _, err := svc.GenerateFor(ctx, "198.51.100.8"); err != nil {
		t.Fatalf("GenerateFor(other ip): unexpected error %v", err)
	}
}

package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/ratelimit"
)

// newSMSLoginTest builds an SMSOTPHandler wired with a per-phone limiter and a
// seeded code, plus a gin engine routing POST /auth/sms/login. Only the
// wrong-code / cap path is exercised, so the success-only deps (users,
// sessionMgr) can stay nil.
func newSMSLoginTest(t *testing.T, maxAttempts int) (*gin.Engine, *miniredis.Miniredis, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	lim, err := ratelimit.New(rdb, ratelimit.Config{
		Purpose: "sms_login", MaxAttempts: maxAttempts,
		Window: 5 * time.Minute, Lockout: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	h := NewSMSOTPHandler(SMSOTPHandlerOpts{
		Redis:      rdb,
		DefaultTID: 1,
		Limiter:    lim,
	})
	const phone = "13800138000"
	// Seed a real code for the phone (user_id 42, code 123456).
	if err := rdb.Set(context.Background(), smsOTPKeyPrefix+phone, "42:123456", 5*time.Minute).Err(); err != nil {
		t.Fatalf("seed code: %v", err)
	}

	r := gin.New()
	r.POST("/auth/sms/login", h.login)
	return r, mr, phone
}

func postSMSLogin(r *gin.Engine, phone, code string) *httptest.ResponseRecorder {
	body := `{"phone":"` + phone + `","code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sms/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// After maxAttempts wrong codes the phone is capped: further attempts return
// 429 instead of letting the attacker keep guessing the 6-digit code within
// its 5-min TTL.
func TestSMSLogin_PerPhoneCap(t *testing.T) {
	const maxAttempts = 5
	r, _, phone := newSMSLoginTest(t, maxAttempts)

	// maxAttempts wrong guesses. The Nth trips the lock and itself returns 429.
	for i := 0; i < maxAttempts; i++ {
		w := postSMSLogin(r, phone, "000000")
		if i < maxAttempts-1 && w.Code != http.StatusBadRequest {
			t.Fatalf("guess %d: want 400 (bad code), got %d", i, w.Code)
		}
	}

	// One more attempt is now hard-blocked by the cap.
	w := postSMSLogin(r, phone, "000000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong guesses want 429, got %d", maxAttempts, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 response must carry a Retry-After header")
	}
}

// Wrong guesses below the cap return 400 (bad code), NOT 429 — the limiter
// only blocks once the threshold is crossed, so a few typos don't lock out a
// legitimate user prematurely.
func TestSMSLogin_UnderCapReturnsBadCode(t *testing.T) {
	r, _, phone := newSMSLoginTest(t, 5)
	// Two wrong guesses, both still under the cap of 5.
	postSMSLogin(r, phone, "111111")
	w := postSMSLogin(r, phone, "222222")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code under the cap must be 400, got %d", w.Code)
	}
}

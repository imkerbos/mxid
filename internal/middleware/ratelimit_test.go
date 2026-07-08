package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func newRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func newRLRouter(rdb *redis.Client, rule RateLimitRule) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RateLimiter(rdb, rule))
	r.POST("/x", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	return r
}

func TestRateLimit_AllowsUnderCap(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "global", Limit: 5, Window: time.Minute, KeyFunc: KeyByClientIP,
	})
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("hit %d should pass, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimit_Rejects429AboveCap(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "global", Limit: 2, Window: time.Minute, KeyFunc: KeyByClientIP,
	})
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third request must 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Errorf("Retry-After header missing")
	}
}

func TestRateLimit_PerKeyIsolation(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "global", Limit: 1, Window: time.Minute, KeyFunc: KeyByClientIP,
	})
	// Two different remote addrs share the limit independently.
	req1 := httptest.NewRequest(http.MethodPost, "/x", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest(http.MethodPost, "/x", nil)
	req2.RemoteAddr = "10.0.0.2:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req2)
	if w.Code != 200 {
		t.Fatalf("different IP must not share bucket, got %d", w.Code)
	}
}

func TestRateLimit_MethodFilter(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "writes", Limit: 1, Window: time.Minute, KeyFunc: KeyByClientIP,
		MethodFilter: AllMutationMethods,
	})
	// GET is not in MethodFilter → unlimited
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		if w.Code != 200 {
			t.Fatalf("GET should bypass write filter, got %d", w.Code)
		}
	}
}

func TestRateLimit_PathFilter(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "sensitive", Limit: 1, Window: time.Minute, KeyFunc: KeyByClientIP,
		PathFilter: []string{"/admin"},
	})
	// /x is not in path filter
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		if w.Code != 200 {
			t.Fatalf("non-matching path should bypass, got %d", w.Code)
		}
	}
}

func TestRateLimit_KeyFuncEmptySkips(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "users", Limit: 1, Window: time.Minute,
		KeyFunc: func(*gin.Context) string { return "" },
	})
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		if w.Code != 200 {
			t.Fatalf("empty key should skip rule, got %d", w.Code)
		}
	}
}

func TestRateLimit_LimitFuncZeroDisables(t *testing.T) {
	rdb, _ := newRedis(t)
	// Static Limit is low (1) but LimitFunc returns 0 => unlimited, should
	// always override the static Limit.
	r := newRLRouter(rdb, RateLimitRule{
		Name: "user", Limit: 1, Window: time.Minute, KeyFunc: KeyByClientIP,
		LimitFunc: func(*gin.Context) int { return 0 },
	})
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		if w.Code != 200 {
			t.Fatalf("hit %d: LimitFunc()==0 must disable the rule, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimit_LimitFuncAppliesPerRequestLimit(t *testing.T) {
	rdb, _ := newRedis(t)
	r := newRLRouter(rdb, RateLimitRule{
		Name: "user", Window: time.Minute, KeyFunc: KeyByClientIP,
		LimitFunc: func(*gin.Context) int { return 2 },
	})
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("hit %d should pass, got %d", i+1, w.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third request over LimitFunc cap must 429, got %d", w.Code)
	}
	var body struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != 42901 {
		t.Fatalf("want code 42901, got %d", body.Code)
	}
}

func TestRateLimit_LimitFuncPerUserIsolation(t *testing.T) {
	rdb, _ := newRedis(t)
	gin.SetMode(gin.TestMode)
	// Mirror production exactly: AuthMiddleware stores an int64 user id under
	// authn.CtxUserID ("user_id"); KeyByUserID reads it via its int64 branch.
	// We replicate the const value here to avoid an import cycle (authn depends
	// on middleware).
	const ctxUserID = "user_id"
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if h := c.GetHeader("X-Test-User"); h != "" {
			uid, _ := strconv.ParseInt(h, 10, 64)
			c.Set(ctxUserID, uid) // int64, as AuthMiddleware sets it
		}
		c.Next()
	})
	r.Use(RateLimiter(rdb, RateLimitRule{
		Name: "user", Window: time.Minute,
		KeyFunc:   KeyByUserID(ctxUserID),
		LimitFunc: func(*gin.Context) int { return 1 },
	}))
	r.POST("/x", func(c *gin.Context) { c.String(200, "ok") })

	post := func(user string) int {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if user != "" {
			req.Header.Set("X-Test-User", user)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// user 1001 (int64): first passes, second trips the limit of 1.
	if code := post("1001"); code != 200 {
		t.Fatalf("user 1001 first request should pass, got %d", code)
	}
	if code := post("1001"); code != http.StatusTooManyRequests {
		t.Fatalf("user 1001 second request should 429, got %d", code)
	}

	// user 1002 (a DIFFERENT int64 id): independent bucket, still passes.
	if code := post("1002"); code != 200 {
		t.Fatalf("user 1002 should have an independent bucket, got %d", code)
	}

	// unauthenticated request (no uid in context) → KeyByUserID returns "" → rule skipped.
	if code := post(""); code != 200 {
		t.Fatalf("unauthenticated request (no uid) should skip the rule, got %d", code)
	}
}

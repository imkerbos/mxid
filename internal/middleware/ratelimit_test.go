package middleware

import (
	"net/http"
	"net/http/httptest"
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

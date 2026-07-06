package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// /readyz returns 200 when DB + Redis are reachable, and 503 when a dependency
// is down — so an unhealthy pod is pulled from the Service.
func TestRegisterReadyz(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	r := gin.New()
	RegisterReadyz(r, db, rdb)

	do := func() int {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return w.Code
	}

	if got := do(); got != http.StatusOK {
		t.Fatalf("healthy: want 200, got %d", got)
	}

	// Redis down → not ready.
	mr.Close()
	if got := do(); got != http.StatusServiceUnavailable {
		t.Fatalf("redis down: want 503, got %d", got)
	}
}

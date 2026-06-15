package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/session"
)

type enrollEnv struct {
	mgr     *session.Manager
	sid     string
	pending bool
	hasMFA  bool
}

func newEnrollEnv(t *testing.T) *enrollEnv {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	sess, _ := mgr.Create(context.Background(), session.NamespaceConsole, 1, 1, "ip", "ua", "password")
	return &enrollEnv{mgr: mgr, sid: sess.ID}
}

func (e *enrollEnv) router() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/console")
	grp.Use(func(c *gin.Context) {
		c.Set(CtxUserID, int64(1))
		c.Set(CtxSessionID, e.sid)
		c.Set(CtxMFAEnrollPending, e.pending)
		c.Next()
	})
	grp.Use(EnrollGateMiddleware(EnrollGateDeps{
		Namespace:  session.NamespaceConsole,
		SessionMgr: e.mgr,
		HasMFA:     func(context.Context, int64) (bool, error) { return e.hasMFA, nil },
	}))
	grp.GET("/users", func(c *gin.Context) { c.Status(http.StatusOK) })
	grp.GET("/security/mfa", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func (e *enrollEnv) get(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestEnrollGate_NotPendingAllows(t *testing.T) {
	e := newEnrollEnv(t)
	e.pending = false
	if got := e.get("/api/v1/console/users").Code; got != 200 {
		t.Fatalf("non-pending must pass, got %d", got)
	}
}

func TestEnrollGate_PendingBlocksNonEnrollRoute(t *testing.T) {
	e := newEnrollEnv(t)
	e.pending = true
	e.hasMFA = false
	if got := e.get("/api/v1/console/users").Code; got != 403 {
		t.Fatalf("pending + no MFA must block other routes, got %d", got)
	}
}

func TestEnrollGate_PendingAllowsMFAEnrollRoute(t *testing.T) {
	e := newEnrollEnv(t)
	e.pending = true
	e.hasMFA = false
	if got := e.get("/api/v1/console/security/mfa").Code; got != 200 {
		t.Fatalf("pending user must reach the MFA enrollment surface, got %d", got)
	}
}

func TestEnrollGate_PendingButEnrolledClearsAndAllows(t *testing.T) {
	e := newEnrollEnv(t)
	_ = e.mgr.SetEnrollPending(context.Background(), session.NamespaceConsole, e.sid, true)
	e.pending = true
	e.hasMFA = true // bound a factor since the flag was set

	if got := e.get("/api/v1/console/users").Code; got != 200 {
		t.Fatalf("enrolled user must pass, got %d", got)
	}
	// The stale flag must be cleared on the persisted session.
	sess, _ := e.mgr.Get(context.Background(), session.NamespaceConsole, e.sid)
	if sess == nil || sess.MFAEnrollPending {
		t.Fatalf("pending flag must be cleared once a factor exists")
	}
}

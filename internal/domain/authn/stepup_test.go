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

func TestIsHighRiskConsole(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"DELETE", "/api/v1/console/users/:id", true},
		{"DELETE", "/api/v1/console/apps/:id", true},
		{"DELETE", "/api/v1/console/groups/:id/members/:uid", true},
		{"PUT", "/api/v1/console/users/:id/super-admin", true},
		{"PUT", "/api/v1/console/users/:id/password", true},
		{"POST", "/api/v1/console/apps/:id/rotate-signing-key", true},
		{"POST", "/api/v1/console/apps/:id/regenerate-secret", true},
		{"POST", "/api/v1/console/users/:id/mfa/lockout/clear", true},
		// not high-risk
		{"GET", "/api/v1/console/users/:id", false},
		{"POST", "/api/v1/console/apps", false},
		{"PUT", "/api/v1/console/users/:id", false},
		// portal / self-service / protocol — never gated
		{"DELETE", "/api/v1/portal/apps/:id/favorite", false},
		{"DELETE", "/api/v1/portal/mfa/totp", false},
		{"POST", "/api/v1/portal/auth/login", false},
	}
	for _, tc := range cases {
		if got := IsHighRiskConsole(tc.method, tc.path); got != tc.want {
			t.Errorf("IsHighRiskConsole(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

type stepUpEnv struct {
	mgr     *session.Manager
	sid     string
	isAdmin bool
	hasMFA  bool
	mode    string
	window  time.Duration
}

func newStepUpEnv(t *testing.T) *stepUpEnv {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	sess, err := mgr.Create(context.Background(), session.NamespaceConsole, 1, 1, "ip", "ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &stepUpEnv{mgr: mgr, sid: sess.ID, mode: "all", window: 30 * time.Minute}
}

func (e *stepUpEnv) router() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	deps := StepUpDeps{
		SessionMgr: e.mgr,
		Policy:     func(_ context.Context, _ int64) (string, time.Duration) { return e.mode, e.window },
		IsAdmin:    func(_ context.Context, _, _ int64) bool { return e.isAdmin },
		HasMFA:     func(_ context.Context, _ int64) (bool, error) { return e.hasMFA, nil },
	}
	grp := r.Group("/api/v1/console")
	grp.Use(func(c *gin.Context) {
		c.Set(CtxUserID, int64(1))
		c.Set(CtxTenantID, int64(1))
		c.Set(CtxSessionID, e.sid)
		c.Next()
	})
	grp.Use(StepUpMiddleware(deps))
	grp.DELETE("/users/:id", func(c *gin.Context) { c.Status(http.StatusOK) })
	grp.GET("/users/:id", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func (e *stepUpEnv) do(method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.router().ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestStepUpMiddleware_ModeOffAllows(t *testing.T) {
	e := newStepUpEnv(t)
	e.mode = "off"
	if got := e.do("DELETE", "/api/v1/console/users/1").Code; got != 200 {
		t.Fatalf("mode off must allow, got %d", got)
	}
}

func TestStepUpMiddleware_NonHighRiskAllows(t *testing.T) {
	e := newStepUpEnv(t)
	e.mode = "all"
	e.hasMFA = false
	if got := e.do("GET", "/api/v1/console/users/1").Code; got != 200 {
		t.Fatalf("GET is not high-risk, must allow, got %d", got)
	}
}

func TestStepUpMiddleware_EnrollRequiredWhenNoMFA(t *testing.T) {
	e := newStepUpEnv(t)
	e.mode = "all"
	e.hasMFA = false
	if got := e.do("DELETE", "/api/v1/console/users/1").Code; got != 403 {
		t.Fatalf("no MFA enrolled must 403, got %d", got)
	}
}

func TestStepUpMiddleware_AdminOnlyExemptsNonAdmin(t *testing.T) {
	e := newStepUpEnv(t)
	e.mode = "admin_only"
	e.isAdmin = false
	e.hasMFA = false
	if got := e.do("DELETE", "/api/v1/console/users/1").Code; got != 200 {
		t.Fatalf("admin_only + non-admin must allow, got %d", got)
	}
}

func TestStepUpMiddleware_ChallengeWhenStale(t *testing.T) {
	e := newStepUpEnv(t)
	e.mode = "all"
	e.hasMFA = true // enrolled but session never passed step-up
	if got := e.do("DELETE", "/api/v1/console/users/1").Code; got != 403 {
		t.Fatalf("stale session must 403 step-up, got %d", got)
	}
}

func TestStepUpMiddleware_AllowsWhenFresh(t *testing.T) {
	e := newStepUpEnv(t)
	e.mode = "all"
	e.hasMFA = true
	if err := e.mgr.MarkMFAVerified(context.Background(), session.NamespaceConsole, e.sid); err != nil {
		t.Fatalf("mark mfa: %v", err)
	}
	if got := e.do("DELETE", "/api/v1/console/users/1").Code; got != 200 {
		t.Fatalf("fresh step-up must allow, got %d", got)
	}
}

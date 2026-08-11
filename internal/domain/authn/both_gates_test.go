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

// A restored account owes both debts at once: the administrator sets a password
// to hand it back (which flags a forced change) and, under an enforce-MFA
// policy, it has no factor because the old one went with the deletion.
//
// Each gate used to allow only its own remediation surface, so the two blocked
// each other — the enrollment call was refused by the password gate and the
// password call by the enrollment gate. The user got both demands on screen and
// no way to satisfy either; the only way out was an administrator editing a
// flag in the database. This is that deadlock.

type bothGatesEnv struct {
	mgr          *session.Manager
	sid          string
	pwdPending   bool
	mfaPending   bool
	stillMustPwd bool
	hasMFA       bool
}

func newBothGatesEnv(t *testing.T) *bothGatesEnv {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	sess, _ := mgr.Create(context.Background(), session.NamespacePortal, 1, 1, "ip", "ua", "password")
	return &bothGatesEnv{
		mgr: mgr, sid: sess.ID,
		pwdPending: true, mfaPending: true,
		stillMustPwd: true, hasMFA: false,
	}
}

// router wires both gates in the order the portal mounts them.
func (e *bothGatesEnv) router() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/portal")
	grp.Use(func(c *gin.Context) {
		c.Set(CtxUserID, int64(1))
		c.Set(CtxSessionID, e.sid)
		c.Set(CtxMFAEnrollPending, e.mfaPending)
		c.Set(CtxPwdChangePending, e.pwdPending)
		c.Next()
	})
	grp.Use(EnrollGateMiddleware(EnrollGateDeps{
		Namespace:  session.NamespacePortal,
		SessionMgr: e.mgr,
		HasMFA:     func(context.Context, int64) (bool, error) { return e.hasMFA, nil },
	}))
	grp.Use(PwdGateMiddleware(PwdGateDeps{
		Namespace:  session.NamespacePortal,
		SessionMgr: e.mgr,
		MustChange: func(context.Context, int64) (bool, error) { return e.stillMustPwd, nil },
	}))
	grp.GET("/apps", func(c *gin.Context) { c.Status(http.StatusOK) })
	grp.POST("/security/mfa/totp/setup", func(c *gin.Context) { c.Status(http.StatusOK) })
	grp.PUT("/security/password", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func (e *bothGatesEnv) do(method, path string) int {
	w := httptest.NewRecorder()
	e.router().ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w.Code
}

func TestBothGates_LeaveAWayOut(t *testing.T) {
	e := newBothGatesEnv(t)

	if got := e.do(http.MethodPost, "/api/v1/portal/security/mfa/totp/setup"); got != http.StatusOK {
		t.Fatalf("a user owing both a password change and an enrollment cannot start TOTP setup (got %d); "+
			"combined with the password path below this is a lockout with no self-service way out", got)
	}
	if got := e.do(http.MethodPut, "/api/v1/portal/security/password"); got != http.StatusOK {
		t.Fatalf("the same user cannot change their password either (got %d); both remediation paths are shut", got)
	}
}

// TestBothGates_StillBlockEverythingElse is the other half: opening the two
// remediation surfaces must not have opened the portal.
func TestBothGates_StillBlockEverythingElse(t *testing.T) {
	e := newBothGatesEnv(t)

	if got := e.do(http.MethodGet, "/api/v1/portal/apps"); got != http.StatusForbidden {
		t.Fatalf("ordinary routes must stay blocked while either debt is outstanding, got %d", got)
	}
}

// TestBothGates_ClearingOneKeepsTheOtherClosed proves the debts are independent:
// binding a factor must not also release the forced password change.
func TestBothGates_ClearingOneKeepsTheOtherClosed(t *testing.T) {
	e := newBothGatesEnv(t)
	e.hasMFA = true // factor bound; enrollment gate self-heals

	if got := e.do(http.MethodGet, "/api/v1/portal/apps"); got != http.StatusForbidden {
		t.Fatalf("password change is still owed, so the portal must stay blocked, got %d", got)
	}
	if got := e.do(http.MethodPut, "/api/v1/portal/security/password"); got != http.StatusOK {
		t.Fatalf("the remaining remediation path must stay reachable, got %d", got)
	}

	// Now settle the password too — the session is finally free.
	e.stillMustPwd = false
	if got := e.do(http.MethodGet, "/api/v1/portal/apps"); got != http.StatusOK {
		t.Fatalf("with both debts settled the portal must open, got %d", got)
	}
}

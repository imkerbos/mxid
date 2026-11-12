package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/session"
)

// A login writes TWO sessions for the same user: the SPA one (portal/console)
// and the shared protocol one the SSO bridge hands to SAML/CAS/OIDC. Both are
// stamped with the same obligation flags at creation.
//
// The gate only ever saw the SPA session id, so settling the debt cleared the
// SPA flag and left the protocol one set. The protocol resolver reports a
// session carrying an unsettled obligation as no session at all, so the user
// who just changed their password had to authenticate again at the next RP
// hop — the whole point of clearing the flag was that they would not.

type protoClearEnv struct {
	mr           *miniredis.Miniredis
	mgr          *session.Manager
	portalSID    string
	protoSID     string
	stillMustPwd bool
}

func newProtoClearEnv(t *testing.T) *protoClearEnv {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	ctx := context.Background()

	portal, err := mgr.Create(ctx, session.NamespacePortal, 7, 1, "ip", "ua", "password")
	if err != nil {
		t.Fatalf("create portal session: %v", err)
	}
	proto, err := mgr.Create(ctx, session.NamespaceProtocol, 7, 1, "ip", "ua", "password")
	if err != nil {
		t.Fatalf("create proto session: %v", err)
	}
	for _, s := range []struct {
		ns, id string
	}{{session.NamespacePortal, portal.ID}, {session.NamespaceProtocol, proto.ID}} {
		if err := mgr.SetPwdChangePending(ctx, s.ns, s.id, true); err != nil {
			t.Fatalf("flag %s: %v", s.ns, err)
		}
	}

	return &protoClearEnv{mr: mr, mgr: mgr, portalSID: portal.ID, protoSID: proto.ID, stillMustPwd: true}
}

func (e *protoClearEnv) do(t *testing.T, method, path string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/portal")
	grp.Use(func(c *gin.Context) {
		c.Set(CtxUserID, int64(7))
		c.Set(CtxSessionID, e.portalSID)
		c.Set(CtxPwdChangePending, true)
		c.Next()
	})
	grp.Use(PwdGateMiddleware(PwdGateDeps{
		Namespace:  session.NamespacePortal,
		SessionMgr: e.mgr,
		MustChange: func(context.Context, int64) (bool, error) { return e.stillMustPwd, nil },
	}))
	grp.GET("/apps", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w.Code
}

func (e *protoClearEnv) protoPending(t *testing.T) bool {
	t.Helper()
	sess, err := e.mgr.Get(context.Background(), session.NamespaceProtocol, e.protoSID)
	if err != nil {
		t.Fatalf("get proto session: %v", err)
	}
	if sess == nil {
		t.Fatal("proto session vanished — clearing a flag must never delete someone's session")
	}
	return sess.PwdChangePending
}

// TestObligationGate_ClearsProtocolNamespace is the regression: settling the
// debt must release the protocol session too, not just the SPA one.
func TestObligationGate_ClearsProtocolNamespace(t *testing.T) {
	e := newProtoClearEnv(t)
	e.stillMustPwd = false // password chosen on a prior request

	if got := e.do(t, http.MethodGet, "/api/v1/portal/apps"); got != http.StatusOK {
		t.Fatalf("settled debt must open the portal, got %d", got)
	}
	if e.protoPending(t) {
		t.Fatal("protocol session still flagged PwdChangePending after the debt settled; " +
			"the resolver reports it as no session, so the next RP hop re-authenticates the user")
	}
}

// TestObligationGate_UnsettledKeepsProtocolFlagged is the other half: clearing
// is a RELAXATION, so it may only happen once the debt is genuinely settled.
func TestObligationGate_UnsettledKeepsProtocolFlagged(t *testing.T) {
	e := newProtoClearEnv(t)

	if got := e.do(t, http.MethodGet, "/api/v1/portal/apps"); got != http.StatusForbidden {
		t.Fatalf("outstanding debt must stay blocked, got %d", got)
	}
	if !e.protoPending(t) {
		t.Fatal("protocol session was released while the password change was still owed")
	}
}

// TestObligationGate_OnlyTouchesItsOwnUser guards the blast radius: another
// user's protocol session must keep its flag.
func TestObligationGate_OnlyTouchesItsOwnUser(t *testing.T) {
	e := newProtoClearEnv(t)
	ctx := context.Background()
	other, err := e.mgr.Create(ctx, session.NamespaceProtocol, 8, 1, "ip", "ua", "password")
	if err != nil {
		t.Fatalf("create other proto session: %v", err)
	}
	if err := e.mgr.SetPwdChangePending(ctx, session.NamespaceProtocol, other.ID, true); err != nil {
		t.Fatalf("flag other: %v", err)
	}

	e.stillMustPwd = false
	if got := e.do(t, http.MethodGet, "/api/v1/portal/apps"); got != http.StatusOK {
		t.Fatalf("settled debt must open the portal, got %d", got)
	}

	got, err := e.mgr.Get(ctx, session.NamespaceProtocol, other.ID)
	if err != nil || got == nil {
		t.Fatalf("get other proto session: %v / %v", err, got)
	}
	if !got.PwdChangePending {
		t.Fatal("another user's protocol session was released")
	}
}

// TestObligationGate_ClearFailureKeepsBlocking pins the fail-closed direction:
// if the settled state cannot be written back, the gate keeps refusing rather
// than letting the request through on an unwritten promise. The remediation
// surface stays reachable so this can never deadlock.
func TestObligationGate_ClearFailureKeepsBlocking(t *testing.T) {
	gin.SetMode(gin.TestMode)
	g := obligationGate{
		namespace: session.NamespacePortal,
		ctxFlag:   CtxPwdChangePending,
		stillOwes: func(context.Context, int64) (bool, error) { return false, nil },
		clearFlag: func(context.Context, string, string, bool) error {
			return errors.New("redis down")
		},
		peerNamespaces: nil,
		sessionsByUser: nil,
		code:           4000,
		message:        "password change required",
	}

	r := gin.New()
	grp := r.Group("/api/v1/portal")
	grp.Use(func(c *gin.Context) {
		c.Set(CtxUserID, int64(7))
		c.Set(CtxSessionID, "sid")
		c.Set(CtxPwdChangePending, true)
		c.Next()
	})
	grp.Use(g.handler())
	grp.GET("/apps", func(c *gin.Context) { c.Status(http.StatusOK) })
	grp.PUT("/security/password", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/portal/apps", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a failed write-back must keep the gate closed, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/portal/security/password", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("remediation surface must stay reachable even then, got %d", w.Code)
	}
}

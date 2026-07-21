package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/session"
)

// Logging out of the portal must invoke the global Single-Logout hook with the
// session's user + tenant, BEFORE the local session is destroyed, so the SP
// fan-out can still read the (about-to-be-deleted) SSO session.
func TestLogoutHandler_InvokesGlobalLogout(t *testing.T) {
	h, sm := newTestHandler(t, false)
	h.engine.eventBus = event.NewBus(zap.NewNop())

	ctx := context.Background()
	const wantUser, wantTenant = int64(7001), int64(1)
	sess, err := sm.Create(ctx, session.NamespacePortal, wantUser, wantTenant, "127.0.0.1", "test-agent", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var gotUser, gotTenant int64
	var called bool
	var sessionAliveAtCall bool
	h.SetGlobalLogout(func(_ context.Context, tenantID, userID int64) {
		called = true
		gotUser, gotTenant = userID, tenantID
		// The SSO session must still exist when the hook runs (OIDC fan-out
		// reads it to enumerate participating RPs).
		if s, e := sm.Get(context.Background(), session.NamespacePortal, sess.ID); e == nil && s != nil {
			sessionAliveAtCall = true
		}
	})

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/portal/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookiePortal, Value: sess.ID})
	c.Request = req

	h.logoutHandler(session.NamespacePortal, CookiePortal)(c)

	if !called {
		t.Fatal("global logout hook was not invoked")
	}
	if gotUser != wantUser || gotTenant != wantTenant {
		t.Fatalf("hook got user=%d tenant=%d, want %d/%d", gotUser, gotTenant, wantUser, wantTenant)
	}
	if !sessionAliveAtCall {
		t.Fatal("hook must run BEFORE the session is deleted (OIDC fan-out needs it)")
	}
	// Session is destroyed by the time logout returns.
	if s, _ := sm.Get(ctx, session.NamespacePortal, sess.ID); s != nil {
		t.Fatal("session should be deleted after logout")
	}
}

// No global-logout hook wired → logout still tears down the local session
// without panicking (fan-out is optional).
func TestLogoutHandler_NoHookIsSafe(t *testing.T) {
	h, sm := newTestHandler(t, false)
	h.engine.eventBus = event.NewBus(zap.NewNop())

	sess, err := sm.Create(context.Background(), session.NamespacePortal, 7002, 1, "127.0.0.1", "ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/portal/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookiePortal, Value: sess.ID})
	c.Request = req

	h.logoutHandler(session.NamespacePortal, CookiePortal)(c)

	if w.Code != http.StatusOK {
		t.Fatalf("logout without hook = %d, want 200", w.Code)
	}
}

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

// newTestHandler builds a Handler backed by miniredis with only the pieces
// ssoHandler needs (session manager + admin checker). GetSession and
// SessionManager().Create touch redis only, so no DB/userRepo is required.
func newTestHandler(t *testing.T, isAdmin bool) (*Handler, *session.Manager) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	sm := session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	h := &Handler{engine: &Engine{sessionMgr: sm}}
	h.SetAdminChecker(func(_ context.Context, _, _ int64) bool { return isAdmin })
	return h, sm
}

func doSSO(t *testing.T, h *Handler, protoCookie string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/console/auth/sso", nil)
	if protoCookie != "" {
		req.AddCookie(&http.Cookie{Name: CookieProto, Value: protoCookie})
	}
	c.Request = req
	h.ssoHandler(session.NamespaceConsole, CookieConsole, true)(c)
	return w
}

// Happy path: a valid proto SSO session + admin user mints a console session
// cookie without re-entering credentials.
func TestSSOHandler_BridgesProtoToConsoleSession(t *testing.T) {
	h, sm := newTestHandler(t, true)
	proto, err := sm.Create(context.Background(), session.NamespaceProtocol, 42, 1, "1.2.3.4", "ua", "password")
	if err != nil {
		t.Fatalf("seed proto session: %v", err)
	}

	w := doSSO(t, h, proto.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var consoleSID string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieConsole {
			consoleSID = ck.Value
		}
	}
	if consoleSID == "" {
		t.Fatalf("expected %s cookie to be set", CookieConsole)
	}
	// The minted session must actually exist in the console namespace and map
	// back to the same user as the proto session.
	sess, err := sm.Get(context.Background(), session.NamespaceConsole, consoleSID)
	if err != nil || sess == nil {
		t.Fatalf("console session not persisted: %v", err)
	}
	if sess.UserID != 42 || sess.TenantID != 1 {
		t.Fatalf("identity not carried over: got user=%d tenant=%d", sess.UserID, sess.TenantID)
	}
}

// No proto session → 401, no console cookie.
func TestSSOHandler_NoProtoSessionUnauthorized(t *testing.T) {
	h, _ := newTestHandler(t, true)
	w := doSSO(t, h, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

// Valid proto session but non-admin user → 403, no console cookie minted.
func TestSSOHandler_NonAdminForbidden(t *testing.T) {
	h, sm := newTestHandler(t, false)
	proto, _ := sm.Create(context.Background(), session.NamespaceProtocol, 7, 1, "1.2.3.4", "ua", "password")
	w := doSSO(t, h, proto.ID)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", w.Code, w.Body.String())
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieConsole && ck.Value != "" {
			t.Fatalf("console cookie must not be set for non-admin")
		}
	}
}

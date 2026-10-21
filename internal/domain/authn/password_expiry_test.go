package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/session"
)

// An expired password must not refuse the login. Refusing it was a dead end:
// the self-service change needs a session the user was never given, the reset
// link needs SMTP the deployment may not have, and what remained was an
// administrator doing it by hand. The person at the prompt has just proved
// they know the current password, which makes them exactly who may choose the
// next one — so authentication succeeds and the obligation rides on the
// session instead (see the PwdChangeDecider wiring and PwdGateMiddleware).
func TestAuthenticate_ExpiredPasswordStillAuthenticates(t *testing.T) {
	hash, _ := crypto.HashPassword("right-pw")
	ancient := time.Now().Add(-365 * 24 * time.Hour)
	q := &enumStubQuerier{
		known: "bob",
		user: &UserAuth{
			ID: 9, Username: "bob", PasswordHash: hash,
			Status: statusActive, PasswordChangedAt: &ancient,
		},
	}
	p := NewLocalProvider(q)

	res, err := p.Authenticate(context.Background(), &AuthRequest{
		TenantID:    1,
		Credentials: map[string]string{"username": "bob", "password": "right-pw"},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.Status != AuthSuccess {
		t.Fatalf("status = %v, want AuthSuccess — an expired password left the user with no way to fix it", res.Status)
	}
}

// A wrong password is still a failure, however old the stored one is. The
// relaxation above applies only to someone who proved knowledge of the current
// password; without that proof there is nothing to justify a session.
func TestAuthenticate_ExpiredPasswordStillRejectsWrongPassword(t *testing.T) {
	hash, _ := crypto.HashPassword("right-pw")
	ancient := time.Now().Add(-365 * 24 * time.Hour)
	q := &enumStubQuerier{
		known: "bob",
		user: &UserAuth{
			ID: 9, Username: "bob", PasswordHash: hash,
			Status: statusActive, PasswordChangedAt: &ancient,
		},
	}
	p := NewLocalProvider(q)

	res, err := p.Authenticate(context.Background(), &AuthRequest{
		TenantID:    1,
		Credentials: map[string]string{"username": "bob", "password": "wrong-pw"},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.Status != AuthFailed {
		t.Fatalf("status = %v, want AuthFailed", res.Status)
	}
}

// A session that owes a password change must NOT be bridged into the protocol
// namespace. PwdGateMiddleware confines such a session to the change-password
// route, but it guards only MXID's own SPA surfaces — the protocol endpoints
// read the protocol-scope session and cannot see the obligation. Bridging
// anyway stopped the user from reaching their own profile page while letting
// them single-sign-on into every downstream application: the gate held the
// door it did not need to hold and left open the one that mattered.
func TestFinalizeLoginCookies_NoProtoSessionWhilePasswordChangePending(t *testing.T) {
	h, sm := newTestHandler(t, false)
	h.tenantID = 1
	sm.SetPwdChangeDecider(func(context.Context, int64, int64) bool { return true })

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/portal/auth/login", nil)

	spa, err := sm.Create(context.Background(), session.NamespacePortal, 42, 1, "1.2.3.4", "UA", "password")
	if err != nil {
		t.Fatalf("create spa session: %v", err)
	}
	if !spa.PwdChangePending {
		t.Fatal("decider did not mark the session — the rest of this test proves nothing")
	}

	h.finalizeLoginCookies(c, session.NamespacePortal, CookiePortal,
		&LoginResponse{UserID: 42, TenantID: 1, SessionID: spa.ID}, "password", false)

	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieProto && ck.Value != "" {
			t.Fatal("a session owing a password change was bridged to the protocol namespace — it can SSO into every downstream application while the gate holds it out of the portal")
		}
	}
}

// The ordinary case still bridges, or every login loses SSO.
func TestFinalizeLoginCookies_BridgesWhenNothingIsOwed(t *testing.T) {
	h, sm := newTestHandler(t, false)
	h.tenantID = 1

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/portal/auth/login", nil)

	spa, err := sm.Create(context.Background(), session.NamespacePortal, 42, 1, "1.2.3.4", "UA", "password")
	if err != nil {
		t.Fatalf("create spa session: %v", err)
	}

	h.finalizeLoginCookies(c, session.NamespacePortal, CookiePortal,
		&LoginResponse{UserID: 42, TenantID: 1, SessionID: spa.ID}, "password", false)

	var found bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieProto && ck.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("no proto-session cookie for a clean login — SSO is broken for everyone")
	}
}

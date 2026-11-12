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

// A session owing a password change IS bridged, and the bridged protocol
// session must carry the obligation: the protocol resolver collapses any
// session with an open obligation to "no session", so nothing downstream is
// issued until the debt is settled. The handler used to skip the bridge
// instead — a second, narrower copy of that rule (it never looked at
// MFAEnrollPending) which also cost the user their SSO session until the next
// login. What this pins is that the flag reaches the protocol namespace,
// because that is what the resolver reads.
func TestFinalizeLoginCookies_BridgedProtoSessionCarriesPwdObligation(t *testing.T) {
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

	var protoID string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieProto {
			protoID = ck.Value
		}
	}
	if protoID == "" {
		t.Fatal("no protocol session was bridged — the obligation now gates at the resolver, so the bridge must still happen")
	}
	proto, err := sm.Get(context.Background(), session.NamespaceProtocol, protoID)
	if err != nil {
		t.Fatalf("read bridged proto session: %v", err)
	}
	if !proto.PwdChangePending {
		t.Fatal("the bridged protocol session does not carry the password-change obligation — the resolver " +
			"would treat it as a clean session and SSO into every downstream application")
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

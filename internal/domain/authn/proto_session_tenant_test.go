package authn

// MED-A regression guard.
//
// finalizeLoginCookies (shared by /auth/login and /auth/mfa/verify) bridges the
// SPA login into a protocol-scope SSO session. That persisted proto-session row
// MUST be stamped with the EFFECTIVE login tenant (loginResp.TenantID, resolved
// from ?tenant=<code>), NOT the handler's hardcoded default tenant (h.tenantID).
// Otherwise a user logging into a non-default tenant gets an SSO session keyed
// to the wrong tenant, driving cross-tenant SSO short-circuit reads at
// /protocol/oidc/authorize and SAML.
//
// These tests drive finalizeLoginCookies against a miniredis-backed session
// manager and read the persisted proto-session back to assert its TenantID.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/session"
)

// finalizeAndReadProtoSession runs finalizeLoginCookies, extracts the
// mxid_proto_sid cookie it set, and loads the persisted proto-session.
func finalizeAndReadProtoSession(t *testing.T, h *Handler, sm *session.Manager, resp *LoginResponse) *session.Session {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/portal/auth/login", nil)

	h.finalizeLoginCookies(c, CookiePortal, resp, "password", false)

	// Pull the proto-session id out of the Set-Cookie the handler emitted.
	var protoID string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieProto {
			protoID = ck.Value
		}
	}
	if protoID == "" {
		t.Fatal("finalizeLoginCookies did not set a proto-session cookie")
	}
	sess, err := sm.Get(context.Background(), session.NamespaceProtocol, protoID)
	if err != nil {
		t.Fatalf("load proto session: %v", err)
	}
	if sess == nil {
		t.Fatal("proto session not found in store")
	}
	return sess
}

// The effective login tenant (loginResp.TenantID) must win over the handler's
// default tenant when a user logs into a non-default tenant.
func TestFinalizeLoginCookies_ProtoSessionUsesEffectiveTenant(t *testing.T) {
	h, sm := newTestHandler(t, false)
	h.tenantID = 1 // handler default tenant

	resp := &LoginResponse{UserID: 42, TenantID: 77} // ?tenant= resolved to 77
	sess := finalizeAndReadProtoSession(t, h, sm, resp)

	if sess.TenantID != 77 {
		t.Fatalf("proto session TenantID=%d, want effective login tenant 77 (not default %d)", sess.TenantID, h.tenantID)
	}
}

// When the login response carries no tenant (<=0), fall back to the handler
// default so legacy/default-tenant logins still get a usable proto-session.
func TestFinalizeLoginCookies_ProtoSessionFallsBackToDefaultTenant(t *testing.T) {
	h, sm := newTestHandler(t, false)
	h.tenantID = 1

	resp := &LoginResponse{UserID: 42, TenantID: 0}
	sess := finalizeAndReadProtoSession(t, h, sm, resp)

	if sess.TenantID != 1 {
		t.Fatalf("proto session TenantID=%d, want default-tenant fallback 1", sess.TenantID)
	}
}

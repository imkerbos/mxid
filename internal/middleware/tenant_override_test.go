package middleware

// MED-B regression guard.
//
// The X-Tenant-ID cross-tenant override MUST require the super_admin domain
// wildcard ("*"), NOT merely tenant.manage. A tenant admin holding only
// tenant.manage in their own tenant must be REJECTED (403) when they try to set
// X-Tenant-ID to act in another tenant; only a super_admin wildcard holder may
// perform the escape. These tests pin that behaviour so a future refactor can't
// silently relax the gate back to tenant.manage.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
)

// fakeBindingProvider returns a fixed permission set for the test principal.
type fakeBindingProvider struct {
	perms map[string]struct{}
}

func (f fakeBindingProvider) EffectiveBindingsForUser(_ context.Context, _, _ int64) ([]authz.EffectiveBinding, error) {
	return []authz.EffectiveBinding{{
		RoleID:      1,
		Permissions: f.perms,
		Source:      "direct",
		ScopeType:   authz.ScopeGlobal,
	}}, nil
}

func newAuthzWith(perms map[string]struct{}) *authz.Service {
	return authz.NewService(fakeBindingProvider{perms: perms}, nil)
}

// runOverride drives the TenantContext middleware with a stubbed authz service
// and the given permission set, asking to override into tenant 99.
func runOverride(t *testing.T, perms map[string]struct{}) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-Tenant-ID", "99")

	// Pre-seed the context the middleware expects: identity + session tenant +
	// the authz service stash.
	c.Set("user_id", int64(7))
	c.Set("tenant_id", int64(1))
	c.Set(authz.CtxAuthzKey, newAuthzWith(perms))

	reached := false
	handlers := []gin.HandlerFunc{TenantContext(), func(c *gin.Context) { reached = true }}
	for _, h := range handlers {
		if c.IsAborted() {
			break
		}
		h(c)
	}
	if reached {
		// effective tenant should now be the override target
		if v, _ := c.Get("tenant_id"); v != int64(99) {
			t.Fatalf("override accepted but tenant_id=%v, want 99", v)
		}
	}
	return w
}

func TestTenantOverride_RejectedForTenantManageOnly(t *testing.T) {
	w := runOverride(t, map[string]struct{}{"tenant.manage": {}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant.manage-only principal: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestTenantOverride_AcceptedForSuperAdminWildcard(t *testing.T) {
	w := runOverride(t, map[string]struct{}{"*": {}})
	if w.Code == http.StatusForbidden {
		t.Fatalf("super_admin wildcard principal must be allowed to override, got 403 (body=%s)", w.Body.String())
	}
}

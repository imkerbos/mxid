package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/authz"
)

// stubBindings grants one global binding holding exactly `perms`.
type stubBindings struct{ perms []string }

func (s stubBindings) EffectiveBindingsForUser(context.Context, int64, int64) ([]authz.EffectiveBinding, error) {
	set := make(map[string]struct{}, len(s.perms))
	for _, p := range s.perms {
		set[p] = struct{}{}
	}
	return []authz.EffectiveBinding{{Permissions: set, ScopeType: authz.ScopeGlobal}}, nil
}

type stubOrgTree struct{}

func (stubOrgTree) IsAncestorOrSelf(context.Context, int64, int64) (bool, error) {
	return false, nil
}

// resolveFor drives resolveTenant through a real gin request carrying a session
// tenant (1), a user id and an authz service holding `perms`.
func resolveFor(t *testing.T, query string, perms []string) (status int, tenant int64) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewHandler(nil, 1)
	svc := authz.NewService(stubBindings{perms: perms}, stubOrgTree{})

	tenant = -1
	r := gin.New()
	r.GET("/dashboard/overview", func(c *gin.Context) {
		c.Set("user_id", int64(42))
		c.Set("tenant_id", int64(1))
		c.Set(authz.CtxAuthzKey, svc)
		if tid, ok := h.resolveTenant(c); ok {
			tenant = tid
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard/overview"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, tenant
}

// ?tenant_id was the ONLY tenant boundary for the dashboard queries (they go
// through .Table(), which bypasses the tenantscope plugin), and it was taken on
// trust: an auditor holding audit.read could export another tenant's audit log.
func TestResolveTenant_NonSuperAdminOverrideRefused(t *testing.T) {
	status, tenant := resolveFor(t, "?tenant_id=2", []string{"audit.read", "user.read", "tenant.manage"})
	if tenant == 2 {
		t.Fatalf("non-super_admin override honoured: scoped to tenant 2 (status=%d)", status)
	}
	if status != http.StatusForbidden {
		t.Fatalf("non-super_admin override: want 403, got %d", status)
	}
}

// super_admin drilldown is a real feature and must keep working.
func TestResolveTenant_SuperAdminOverrideHonoured(t *testing.T) {
	status, tenant := resolveFor(t, "?tenant_id=2", []string{"*"})
	if tenant != 2 {
		t.Fatalf("super_admin override: tenant = %d, want 2 (status=%d)", tenant, status)
	}
}

// No override → the caller's own tenant, untouched.
func TestResolveTenant_NoOverrideUsesSessionTenant(t *testing.T) {
	if _, tenant := resolveFor(t, "", []string{"audit.read"}); tenant != 1 {
		t.Fatalf("no override: tenant = %d, want the session tenant 1", tenant)
	}
}

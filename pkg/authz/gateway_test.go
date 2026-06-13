package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// gwProvider is a binding provider that grants a fixed permission set globally.
type gwProvider struct{ perms []string }

func (p gwProvider) EffectiveBindingsForUser(_ context.Context, _, _ int64) ([]EffectiveBinding, error) {
	set := make(map[string]struct{}, len(p.perms))
	for _, c := range p.perms {
		set[c] = struct{}{}
	}
	return []EffectiveBinding{{RoleID: 1, Permissions: set, ScopeType: ScopeGlobal}}, nil
}

// resetRegistry clears the process-global registry so each test is isolated.
func resetRegistry() {
	registry.mu.Lock()
	registry.protected = make(map[string]string)
	registry.allow = make(map[string]bool)
	registry.allowPfx = nil
	registry.mu.Unlock()
}

// buildHardGatewayEngine wires a console group like main.go but in HARD mode
// (AuditOnly:false) so the deny-by-default behaviour is exercised. Gated routes
// register deterministically at mount via authz.Protect (the stable API the
// backfill agents use); one console route is left UNregistered on purpose.
func buildHardGatewayEngine(t *testing.T) *gin.Engine {
	t.Helper()
	resetRegistry()
	gin.SetMode(gin.TestMode)

	svc := NewService(gwProvider{perms: []string{"app.read"}}, nil)

	r := gin.New()
	console := r.Group("/api/v1/console")
	console.Use(func(c *gin.Context) { // auth shim
		c.Set("user_id", int64(42))
		c.Set("tenant_id", int64(1))
		c.Next()
	})
	Install(console, svc)
	console.Use(Gateway(GatewayConfig{Logger: nil, AuditOnly: false}))

	// Registered + permission held → passes.
	console.GET("/apps", Require("app.read", nil), func(c *gin.Context) {
		c.String(http.StatusOK, "apps-ok")
	})
	Protect(http.MethodGet, "/api/v1/console/apps", "app.read")

	// Registered + permission NOT held → Require denies (gateway must not weaken it).
	console.DELETE("/apps/:id", Require("app.delete", nil), func(c *gin.Context) {
		c.String(http.StatusOK, "deleted")
	})
	Protect(http.MethodDelete, "/api/v1/console/apps/:id", "app.delete")

	// UNREGISTERED console route — author forgot authz. Gateway must 403 it.
	console.POST("/idps", func(c *gin.Context) {
		c.String(http.StatusOK, "created-an-idp-with-no-authz")
	})

	// Explicitly allow-listed public route.
	console.GET("/whoami", func(c *gin.Context) {
		c.String(http.StatusOK, "me")
	})
	AllowPublic(http.MethodGet, "/api/v1/console/whoami")

	return r
}

func do(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestGateway_RegisteredRouteWithPermPasses(t *testing.T) {
	r := buildHardGatewayEngine(t)
	w := do(r, http.MethodGet, "/api/v1/console/apps")
	if w.Code != http.StatusOK {
		t.Fatalf("registered route with held perm: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if w.Body.String() != "apps-ok" {
		t.Fatalf("handler did not run: body=%q", w.Body.String())
	}
}

func TestGateway_UnregisteredConsoleRouteDenied(t *testing.T) {
	r := buildHardGatewayEngine(t)
	w := do(r, http.MethodPost, "/api/v1/console/idps")
	if w.Code != http.StatusForbidden {
		t.Fatalf("unregistered console route: want 403 (deny-by-default), got %d (%s)", w.Code, w.Body.String())
	}
	if w.Body.String() == "created-an-idp-with-no-authz" {
		t.Fatal("SECURITY: unprotected handler executed — deny-by-default failed")
	}
}

func TestGateway_RegisteredRouteWithoutPermStillEnforced(t *testing.T) {
	// Gateway lets the route through; the route's own Require denies because the
	// caller lacks app.delete. Proves the gateway does not weaken Require.
	r := buildHardGatewayEngine(t)
	w := do(r, http.MethodDelete, "/api/v1/console/apps/9")
	if w.Code != http.StatusForbidden {
		t.Fatalf("held-perm-missing: want 403 from Require, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestGateway_AllowListedRoutePasses(t *testing.T) {
	r := buildHardGatewayEngine(t)
	w := do(r, http.MethodGet, "/api/v1/console/whoami")
	if w.Code != http.StatusOK {
		t.Fatalf("allow-listed route: want 200, got %d", w.Code)
	}
}

func TestGateway_AuditOnlyAllowsButRequireSelfRegisters(t *testing.T) {
	// In AuditOnly mode an unregistered gated route is allowed through on its
	// first hit, and Require self-registers it so the registry learns the route.
	resetRegistry()
	gin.SetMode(gin.TestMode)
	svc := NewService(gwProvider{perms: []string{"app.read"}}, nil)
	r := gin.New()
	console := r.Group("/api/v1/console")
	console.Use(func(c *gin.Context) {
		c.Set("user_id", int64(42))
		c.Set("tenant_id", int64(1))
		c.Next()
	})
	Install(console, svc)
	console.Use(Gateway(GatewayConfig{Logger: nil, AuditOnly: true}))
	// Gated with Require but NO mount-time Protect — relies on self-registration.
	console.GET("/apps", Require("app.read", nil), func(c *gin.Context) {
		c.String(http.StatusOK, "apps-ok")
	})

	if registry.isProtected(http.MethodGet, "/api/v1/console/apps") {
		t.Fatal("route should not be registered before first request")
	}
	w := do(r, http.MethodGet, "/api/v1/console/apps")
	if w.Code != http.StatusOK {
		t.Fatalf("audit-only first hit: want 200, got %d", w.Code)
	}
	if !registry.isProtected(http.MethodGet, "/api/v1/console/apps") {
		t.Fatal("Require did not self-register the route at request time")
	}
}

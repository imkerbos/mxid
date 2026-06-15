package authz

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CtxAuthzKey is the gin.Context key under which the authz Service stash es
// itself once installed. Handlers that need to do conditional checks
// (e.g. show different list filters) can retrieve it via FromContext.
const CtxAuthzKey = "mxid:authz"

// Install wires the service into every request so handlers can call
// FromContext(c) and ad-hoc Require* helpers can recover it. Mount this
// once on the protected route group BEFORE any handler-attached middleware
// (e.g. per-route Require) so the route-bound closures still see the
// injected value at request time.
func Install(rg gin.IRoutes, svc *Service) gin.IRoutes {
	return rg.Use(func(c *gin.Context) {
		c.Set(CtxAuthzKey, svc)
		c.Next()
	})
}

// InstallLazy is the bootstrap-friendly variant: it installs the request
// middleware immediately (so domain modules registering routes afterwards
// pick it up) but resolves the Service from the provided function on each
// request. This lets `main` install the middleware BEFORE the service is
// fully wired (domain modules are needed to build it).
//
// The provider closure is expected to start returning a non-nil Service
// once the bootstrap is finished; until then, FromContext returns nil and
// Require/RequireAny will respond with "authz not installed".
func InstallLazy(rg gin.IRoutes, provider func() *Service) gin.IRoutes {
	return rg.Use(func(c *gin.Context) {
		svc := provider()
		c.Set(CtxAuthzKey, svc)
		c.Next()
	})
}

// FromContext fetches the service stashed by Install. Returns nil if the
// middleware was not mounted — Require* helpers treat that as fail-closed.
func FromContext(c *gin.Context) *Service {
	v, ok := c.Get(CtxAuthzKey)
	if !ok {
		return nil
	}
	svc, _ := v.(*Service)
	return svc
}

// TenantIDFromCtx / UserIDFromCtx mirror the keys set by authn middleware.
// Defined here so authz doesn't import authn (which would create a cycle
// with anyone importing both).
func tenantIDFromCtx(c *gin.Context) int64 {
	v, ok := c.Get("tenant_id")
	if !ok {
		return 0
	}
	id, _ := v.(int64)
	return id
}

func userIDFromCtx(c *gin.Context) int64 {
	v, ok := c.Get("user_id")
	if !ok {
		return 0
	}
	id, _ := v.(int64)
	return id
}

// ScopeFn produces the ScopeTarget for a request. Returning nil means
// "no scope target" (the check still verifies the user holds the perm
// somewhere). Receives the same gin context the handler will see, so it
// can parse :id path params.
type ScopeFn func(c *gin.Context) *ScopeTarget

// Require returns a middleware that enforces `perm` against the optional
// scope derived from the request. scopeFn may be nil for permissions that
// are not scope-aware (e.g. role.read).
//
// On deny: 403 with a short JSON body and abort. On the lookup-error path
// the middleware also aborts with 500 — the engine is the source of truth
// and a transient failure should not silently let requests through.
func Require(perm string, scopeFn ScopeFn) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Self-register this route into the deny-by-default gateway registry so
		// AuditOnly logging stays accurate (hard mode relies on mount-time
		// Protect()). Idempotent.
		requestRegister(c.Request.Method, c.FullPath(), perm)
		c.Set(declaredKey, true)
		svc := FromContext(c)
		if svc == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"code":    50000,
				"message": "authz not installed",
			})
			return
		}
		uid := userIDFromCtx(c)
		if uid == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    40101,
				"message": "not authenticated",
			})
			return
		}
		tid := tenantIDFromCtx(c)
		var target *ScopeTarget
		if scopeFn != nil {
			target = scopeFn(c)
		}
		ok, err := svc.Check(c.Request.Context(), tid, uid, perm, target)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"code":    50001,
				"message": "authz check failed: " + err.Error(),
			})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    40300,
				"message": "permission denied: " + perm,
			})
			return
		}
		c.Next()
	}
}

// RequireAny is the OR variant: caller passes a list of permissions and the
// request is allowed if ANY of them check out. Useful when an endpoint serves
// both a manager (full perm) and a self-service caller (limited perm).
func RequireAny(perms []string, scopeFn ScopeFn) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Self-register (perm "" — the OR-set is not a single code; the gateway
		// only needs to know the route is protected).
		requestRegister(c.Request.Method, c.FullPath(), "")
		c.Set(declaredKey, true)
		svc := FromContext(c)
		if svc == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"code": 50000, "message": "authz not installed",
			})
			return
		}
		uid := userIDFromCtx(c)
		if uid == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code": 40101, "message": "not authenticated",
			})
			return
		}
		tid := tenantIDFromCtx(c)
		var target *ScopeTarget
		if scopeFn != nil {
			target = scopeFn(c)
		}
		for _, p := range perms {
			ok, err := svc.Check(c.Request.Context(), tid, uid, p, target)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"code": 50001, "message": "authz check failed",
				})
				return
			}
			if ok {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"code": 40300, "message": "permission denied",
		})
	}
}

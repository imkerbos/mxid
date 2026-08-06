// Package middleware provides reusable gin middlewares.
//
// TenantContext extends the session-derived tenant_id with optional
// super_admin override via X-Tenant-ID header. The override is allowed only
// when authz.Check confirms the caller has the wildcard permission "*"
// (super_admin trait) — tenant admins cannot escape their own tenant.
package middleware

import (
	"github.com/imkerbos/mxid/pkg/errcode"
	"github.com/imkerbos/mxid/pkg/response"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// TenantContext reads X-Tenant-ID header and, if the caller is super_admin,
// overrides the session-bound tenant_id in gin.Context. Place AFTER the
// auth middleware and authz install.
//
// Lookup precedence inside gin.Context after this middleware:
//
//	tenant_id (effective) — what handlers MUST use for filtering
//	session_tenant_id     — original session tenant_id (audit reference)
//
// Handlers that don't care about the override continue reading "tenant_id".
func TenantContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Preserve the session-bound tenant under a separate key so audit
		// can still log "actor's home tenant" even when acting on another.
		if v, ok := c.Get("tenant_id"); ok {
			c.Set("session_tenant_id", v)
		}

		override := c.GetHeader("X-Tenant-ID")
		if override == "" {
			c.Next()
			return
		}
		tid, err := strconv.ParseInt(override, 10, 64)
		if err != nil || tid <= 0 {
			response.BadRequest(c, errcode.NumBadRequest, "invalid X-Tenant-ID")
			c.Abort()
			return
		}

		// Verify the caller is a super_admin before allowing the cross-tenant
		// override. The gate MUST require the domain wildcard "*" (the
		// super_admin trait per pkg/authz) — a tenant admin holding only
		// tenant.manage in their own tenant must NOT be able to set X-Tenant-ID
		// to escape into another tenant. tenant.manage stays sufficient for
		// same-tenant ops; it is just not enough to authorize the escape.
		svc := authz.FromContext(c)
		if svc == nil {
			response.Error(c, http.StatusInternalServerError, errcode.NumNotConfigured,
				"authz not installed", "")
			c.Abort()
			return
		}
		uidV, _ := c.Get("user_id")
		uid, _ := uidV.(int64)
		stidV, _ := c.Get("session_tenant_id")
		stid, _ := stidV.(int64)
		ok, err := svc.Check(c.Request.Context(), stid, uid, "*", nil)
		if err != nil || !ok {
			response.Forbidden(c, errcode.NumForbidden, "tenant override requires super_admin")
			c.Abort()
			return
		}
		c.Set("tenant_id", tid)
		// Re-pin the std context to the chosen tenant so the gorm
		// tenant-isolation plugin scopes queries to the override target
		// rather than the super_admin's home tenant stamped by AuthMiddleware.
		// The admin acts AS that tenant, so this is a normal tenant pin (not a
		// cross-tenant escape).
		c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), tid))
		c.Next()
	}
}

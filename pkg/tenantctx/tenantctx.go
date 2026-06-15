// Package tenantctx exposes a tiny helper to read the request's effective
// tenant_id from gin.Context. Every domain handler should call FromContext
// instead of hard-coding `tenantID = 1` so the multi-tenant switcher works.
package tenantctx

import "github.com/gin-gonic/gin"

// FromContext returns the effective tenant_id for the current request.
// Precedence:
//
//  1. Value set by middleware.TenantContext (super_admin X-Tenant-ID override)
//  2. Session tenant_id set by authn middleware
//  3. fallback (passed in)
//
// fallback is typically 1 (default tenant) so dev / single-tenant mode still
// works without any header gymnastics.
func FromContext(c *gin.Context, fallback int64) int64 {
	if v, ok := c.Get("tenant_id"); ok {
		if id, ok := v.(int64); ok && id > 0 {
			return id
		}
	}
	return fallback
}

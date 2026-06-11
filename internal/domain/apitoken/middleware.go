package apitoken

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
)

// Context keys for downstream handlers to read the token's identity +
// scope set. We intentionally mirror the authn middleware's keys for
// user_id / tenant_id so handlers that look those up don't have to know
// whether the caller used a session cookie or a PAT.
const (
	CtxUserID   = "user_id"
	CtxTenantID = "tenant_id"
	CtxScopes   = "api_token_scopes"
	CtxTokenID  = "api_token_id"
)

// AuthMiddleware returns a gin middleware that:
//   1. Requires Authorization: Bearer mxidpat_...
//   2. Looks up + validates the token via the apitoken service
//   3. Stamps user_id/tenant_id/scopes into the gin context
//
// Failures emit a JSON 401 — never silently fall through, because
// /openapi/v1 has no session-cookie fallback (callers are scripts).
func AuthMiddleware(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			response.Unauthorized(c, 40101, "authorization header required")
			c.Abort()
			return
		}
		if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			response.Unauthorized(c, 40101, "bearer token required")
			c.Abort()
			return
		}
		token, err := svc.Authenticate(c.Request.Context(), header)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer")
			response.Error(c, http.StatusUnauthorized, 40101, "invalid api token", err.Error())
			c.Abort()
			return
		}
		c.Set(CtxUserID, token.UserID)
		c.Set(CtxTenantID, token.TenantID)
		c.Set(CtxScopes, ScopesOf(token))
		c.Set(CtxTokenID, token.ID)
		c.Next()
	}
}

// RequireScope is a per-route middleware that enforces a scope code is
// present in the token's scope set. Tokens with the literal "*" scope pass
// every check (super-admin convenience).
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, exists := c.Get(CtxScopes)
		if !exists {
			response.Forbidden(c, 40301, "no scopes on token")
			c.Abort()
			return
		}
		scopes, _ := raw.([]string)
		for _, s := range scopes {
			if s == "*" || s == scope {
				c.Next()
				return
			}
		}
		response.Forbidden(c, 40301, "token missing required scope: "+scope)
		c.Abort()
	}
}

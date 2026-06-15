// Package feature provides the EE feature-gate gin middleware in an
// importable (non-internal) location so EE feature packages living in the
// separate github.com/imkerbos/mxid-ee module can gate their own routes — the
// CE-internal internal/middleware package is not importable across modules.
//
// It is a leaf: it depends only on the license verifier + the response helper,
// never on internal/bootstrap, so internal/middleware can safely delegate to it
// without an import cycle (bootstrap imports middleware).
package feature

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/response"
)

// RequireFeature gates a route on an EE license feature. In CE (or with an
// invalid/expired license) the feature is locked and the route returns 403.
// Mount it on write/create routes for EE-only capabilities; reads can stay open
// so CE still sees defaults.
func RequireFeature(f license.Feature) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !license.Current().Has(f) {
			// Dedicated code (not the generic 40301) so the frontend can localize
			// this specific case. The English text is only a fallback.
			response.Forbidden(c, 40332, "this feature requires an Enterprise Edition license")
			c.Abort()
			return
		}
		c.Next()
	}
}

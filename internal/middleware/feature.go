package middleware

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
			response.Forbidden(c, 40301, "this feature requires an Enterprise Edition license")
			c.Abort()
			return
		}
		c.Next()
	}
}

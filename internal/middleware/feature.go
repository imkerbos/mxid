package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/ee/feature"
	"github.com/imkerbos/mxid/pkg/ee/license"
)

// RequireFeature gates a route on an EE license feature. In CE (or with an
// invalid/expired license) the feature is locked and the route returns 403.
// Mount it on write/create routes for EE-only capabilities; reads can stay open
// so CE still sees defaults.
//
// The implementation lives in pkg/ee/feature so EE feature packages (separate
// module) can reuse it; this is a thin alias kept so existing CE call sites
// (middleware.RequireFeature) stay unchanged.
func RequireFeature(f license.Feature) gin.HandlerFunc {
	return feature.RequireFeature(f)
}

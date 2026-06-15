// Package public exposes pre-auth endpoints both SPAs use to bootstrap:
//
//   GET /api/v1/system/bootstrap → branding + login methods + i18n
//
// This is intentionally unauthenticated (login pages need it BEFORE the
// user is signed in) and root-mounted (NOT under /portal or /console)
// because both SPAs need it and the response shape is identical.
package public

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/pkg/response"
)

// BootstrapInfo is the JSON shape served to the SPA on app start.
type BootstrapInfo struct {
	Branding     setting.Branding     `json:"branding"`
	LoginMethods setting.LoginMethods `json:"login_methods"`
	Localization setting.Localization `json:"localization"`
}

// Register mounts the public bootstrap route. defaultTID is used because
// pre-auth callers have no tenant context — they get the platform
// default's settings (the tenant the operator configured for the public
// login page).
func Register(r *gin.Engine, settings *setting.Service, defaultTID int64) {
	r.GET("/api/v1/system/bootstrap", func(c *gin.Context) {
		// Pre-auth (no tenant scope in context). settings.* now auto-scopes by the
		// explicit defaultTID inside setting.Service.getRaw (the root-cause fix),
		// so a bare request context reads the right tenant's config here.
		branding, _ := settings.Branding(c.Request.Context(), defaultTID)
		methods, _ := settings.LoginMethods(c.Request.Context(), defaultTID)
		l10n, _ := settings.Localization(c.Request.Context(), defaultTID)
		response.OK(c, BootstrapInfo{
			Branding:     branding,
			LoginMethods: methods,
			Localization: l10n,
		})
	})
}

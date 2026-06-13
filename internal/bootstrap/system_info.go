package bootstrap

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/response"
)

// SystemInfo is the payload of GET /api/v1/system/info — public metadata the
// frontends need before authentication (and that admins copy-paste from the
// in-console docs page).
//
// All URLs are absolute and externally reachable; frontends MUST use them
// verbatim instead of guessing from window.location.origin (which breaks
// under reverse proxies, custom paths, or single-domain deploys where the
// console lives at /admin).
type SystemInfo struct {
	// IssuerURL is the root for protocol endpoints. OIDC discovery doc lives
	// at {IssuerURL}/protocol/oidc/{app}/.well-known/openid-configuration.
	IssuerURL string `json:"issuer_url"`
	// PortalURL is where end users land for login / consent.
	PortalURL string `json:"portal_url"`
	// ConsoleURL is where admins manage the IDP. May equal PortalURL when
	// the operator runs a single-domain deploy.
	ConsoleURL string `json:"console_url"`
	// Version is the MXID build tag. Empty during dev.
	Version string `json:"version,omitempty"`
	// Edition is "ce" or "ee" — drives which features the frontend exposes.
	Edition string `json:"edition"`
	// Features lists the unlocked EE feature keys (empty in CE). The console
	// gates EE-only UI on these.
	Features []string `json:"features"`
}

// RegisterSystemInfo wires GET /api/v1/system/info on the root engine.
// Intentionally NOT under /api/v1/console or /api/v1/portal because the
// portal SPA login page needs it before any session exists.
func RegisterSystemInfo(r *gin.Engine, cfg *ServerConfig, version string) {
	base := SystemInfo{
		IssuerURL:  firstNonEmpty(cfg.IssuerURL, cfg.PortalURL),
		PortalURL:  cfg.PortalURL,
		ConsoleURL: firstNonEmpty(cfg.ConsoleURL, cfg.PortalURL),
		Version:    version,
	}
	r.GET("/api/v1/system/info", func(c *gin.Context) {
		// Edition read live so a runtime license swap reflects without restart.
		info := base
		lic := license.Current()
		info.Edition = string(lic.Edition())
		info.Features = featureStrings(lic.EnabledFeatures())
		response.OK(c, info)
	})
}

func featureStrings(fs []license.Feature) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, string(f))
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

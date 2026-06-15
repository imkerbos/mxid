// Package system exposes console-only system endpoints. Currently the
// read-only update check: show the running build + whether a newer release
// exists. Gated by the "system.read" permission, which in practice only
// super_admin (the "*" wildcard) holds — version/update info is platform-level,
// not tenant-level.
package system

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/updatecheck"
)

type Handler struct {
	checker *updatecheck.Checker
}

func NewHandler(c *updatecheck.Checker) *Handler {
	return &Handler{checker: c}
}

// Register mounts the routes under the console group (/api/v1/console).
func (h *Handler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/system")
	{
		// Cached status — cheap, safe to hit on page load.
		g.GET("/version", authz.Require("system.read", nil), h.getVersion)
		// Force a live re-check (the "check now" button); bypasses the cache.
		g.POST("/version/check", authz.Require("system.read", nil), h.checkVersion)
	}
}

func (h *Handler) getVersion(c *gin.Context) {
	response.OK(c, h.checker.Status(c.Request.Context()))
}

func (h *Handler) checkVersion(c *gin.Context) {
	response.OK(c, h.checker.Check(c.Request.Context()))
}

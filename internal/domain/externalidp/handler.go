package externalidp

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// AdminHandler exposes CRUD over external IdPs to the console.
//
// All routes here are mounted under /api/v1/console/external-idps. Permission
// gating is applied at register time (role.permission.manage / role.read) so
// only platform admins can edit IdP configuration.
type AdminHandler struct {
	svc      *Service
	tenantID int64
}

// NewAdminHandler returns a handler for the console-side IdP routes.
func NewAdminHandler(svc *Service, tenantID int64) *AdminHandler {
	return &AdminHandler{svc: svc, tenantID: tenantID}
}

// RegisterRoutes mounts the admin endpoints. Caller decides authz middleware.
func (h *AdminHandler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/external-idps")
	{
		g.GET("", authz.Require("idp.read", nil), h.List)
		g.GET("/types", authz.Require("idp.read", nil), h.ListTypes)
		g.POST("", authz.Require("idp.create", nil), h.Create)
		g.GET("/:id", authz.Require("idp.read", nil), h.Get)
		g.PUT("/:id", authz.Require("idp.update", nil), h.Update)
		g.DELETE("/:id", authz.Require("idp.delete", nil), h.Delete)
	}
}

func (h *AdminHandler) List(c *gin.Context) {
	items, err := h.svc.List(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), false)
	if err != nil {
		response.InternalError(c, "list idps: "+err.Error())
		return
	}
	response.OK(c, items)
}

// ListTypes surfaces the provider type identifiers the build supports, so
// the create form can render a dropdown.
func (h *AdminHandler) ListTypes(c *gin.Context) {
	response.OK(c, DefaultRegistry.Types())
}

func (h *AdminHandler) Create(c *gin.Context) {
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	idp, err := h.svc.Create(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), &req)
	if err != nil {
		if errors.Is(err, ErrIDPCodeExists) {
			response.Error(c, http.StatusConflict, 40901, err.Error(), "")
			return
		}
		response.BadRequest(c, 40002, err.Error())
		return
	}
	response.Created(c, idp)
}

func (h *AdminHandler) Get(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40001, "invalid id")
		return
	}
	idp, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, ErrIDPNotFound) {
			response.NotFound(c, 40401, err.Error())
			return
		}
		response.InternalError(c, "")
		return
	}
	response.OK(c, idp)
}

func (h *AdminHandler) Update(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40001, "invalid id")
		return
	}
	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	idp, err := h.svc.Update(c.Request.Context(), id, &req)
	if err != nil {
		if errors.Is(err, ErrIDPNotFound) {
			response.NotFound(c, 40401, err.Error())
			return
		}
		response.BadRequest(c, 40002, err.Error())
		return
	}
	response.OK(c, idp)
}

func (h *AdminHandler) Delete(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40001, "invalid id")
		return
	}
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, nil)
}

func parseID(c *gin.Context, name string) (int64, error) {
	return strconv.ParseInt(c.Param(name), 10, 64)
}

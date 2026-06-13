package tenant

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
)

// Handler exposes tenant CRUD endpoints. All gated by `tenant.manage`
// permission which is held by super_admin only — tenant admins MUST NOT
// be able to create/delete other tenants.
type Handler struct {
	svc *Service
}

// NewHandler wires the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// RegisterRoutes mounts /tenants under the console group. Caller decides
// authz middleware — typically `tenant.manage`.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/tenants")
	{
		// list + get + getByCode are read-only and exposed to ANY authenticated
		// console user so the tenant switcher dropdown works for tenant_admin
		// (who needs to see at least their own row).
		g.GET("", h.List)
		g.GET("/:id", h.Get)
		// write ops gated to super_admin via tenant.manage permission.
		g.POST("", authz.Require("tenant.manage", nil), h.Create)
		g.PUT("/:id", authz.Require("tenant.manage", nil), h.Update)
		g.DELETE("/:id", authz.Require("tenant.manage", nil), h.Delete)
	}
}

func (h *Handler) List(c *gin.Context) {
	items, err := h.svc.List(c.Request.Context())
	if err != nil {
		response.InternalError(c, "list tenants: "+err.Error())
		return
	}
	response.OK(c, items)
}

func (h *Handler) Get(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid tenant id")
		return
	}
	t, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			response.NotFound(c, 40401, err.Error())
			return
		}
		response.InternalError(c, "")
		return
	}
	response.OK(c, t)
}

func (h *Handler) Create(c *gin.Context) {
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	t, err := h.svc.Create(c.Request.Context(), &req)
	if err != nil {
		if errors.Is(err, ErrTenantCodeExists) {
			response.Error(c, http.StatusConflict, 40901, err.Error(), "")
			return
		}
		if errors.Is(err, ErrLicenseQuotaExceeded) {
			response.Error(c, http.StatusPaymentRequired, 40201, err.Error(), "")
			return
		}
		response.BadRequest(c, 40002, err.Error())
		return
	}
	response.Created(c, t)
}

func (h *Handler) Update(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid tenant id")
		return
	}
	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	t, err := h.svc.Update(c.Request.Context(), id, &req)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			response.NotFound(c, 40401, err.Error())
			return
		}
		response.InternalError(c, "")
		return
	}
	response.OK(c, t)
}

func (h *Handler) Delete(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid tenant id")
		return
	}
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		response.BadRequest(c, 40002, err.Error())
		return
	}
	response.OK(c, nil)
}

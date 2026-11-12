package dashboard

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/errcode"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler serves the console dashboard endpoints.
type Handler struct {
	svc      *Service
	tenantID int64
}

// NewHandler creates a dashboard handler. defaultTenantID is the fallback when
// the request carries no tenant context.
func NewHandler(svc *Service, defaultTenantID int64) *Handler {
	return &Handler{svc: svc, tenantID: defaultTenantID}
}

// RegisterRoutes mounts the dashboard routes.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	// Read-only admin overview + audit export. Gated so a bare authenticated
	// console session can't scrape tenant-wide stats or stream the audit log
	// without the corresponding read permission (super_admin passes via `*`).
	d := rg.Group("/dashboard")
	{
		d.GET("/overview", authz.Require("user.read", nil), h.Overview)
		d.GET("/export", authz.Require("audit.read", nil), h.Export)
	}
}

// Overview handles GET /dashboard/overview?range=7|30&tenant_id=<id>.
//
// range selects the metric window in days (default 7, capped at 90). tenant_id
// is an optional super-admin drilldown override; absent it uses the caller's
// tenant context.
func (h *Handler) Overview(c *gin.Context) {
	rangeDays := 7
	if r := c.Query("range"); r != "" {
		if n, err := strconv.Atoi(r); err == nil && n > 0 {
			rangeDays = n
		}
	}
	if rangeDays > 90 {
		rangeDays = 90
	}

	tenantID, ok := h.resolveTenant(c)
	if !ok {
		return
	}

	ov, err := h.svc.Overview(c.Request.Context(), tenantID, rangeDays)
	if err != nil {
		response.InternalError(c, "failed to build dashboard overview", err)
		return
	}
	response.OK(c, ov)
}

// Export handles GET /dashboard/export?range=7 — streams the range's audit log
// as CSV for offline analysis / compliance archival (Tier 3).
func (h *Handler) Export(c *gin.Context) {
	rangeDays := 7
	if r := c.Query("range"); r != "" {
		if n, err := strconv.Atoi(r); err == nil && n > 0 {
			rangeDays = n
		}
	}
	if rangeDays > 365 {
		rangeDays = 365
	}
	since := time.Now().AddDate(0, 0, -rangeDays)

	tenantID, ok := h.resolveTenant(c)
	if !ok {
		return
	}

	rows, err := h.svc.ExportAudit(c.Request.Context(), tenantID, since)
	if err != nil {
		response.InternalError(c, "failed to export audit log", err)
		return
	}

	filename := fmt.Sprintf("mxid-audit-%s.csv", time.Now().Format("20060102"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	// Excel-friendly UTF-8 BOM so Chinese actor names render correctly.
	_, _ = c.Writer.WriteString("\xEF\xBB\xBF")

	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{"time", "event_type", "status", "actor", "resource_type", "resource_id", "ip", "country"})
	for _, r := range rows {
		_ = w.Write([]string{
			r.CreatedAt.Format(time.RFC3339),
			r.EventType,
			statusLabel(r.EventStatus),
			deref(r.ActorName),
			deref(r.ResourceType),
			resourceIDStr(r.ResourceID),
			deref(r.IP),
			deref(r.GeoCountry),
		})
	}
	c.Status(http.StatusOK)
}

// resolveTenant returns the tenant to scope metrics to: the caller's tenant
// context by default, or the explicit ?tenant_id when the caller is a
// super_admin drilling down.
//
// These queries go through .Table(), which bypasses the tenantscope plugin, so
// this value is the only tenant boundary they have. It was taken on trust,
// which let anyone who could reach the routes (audit.read is enough for the CSV
// export) read another tenant's data. The gate mirrors
// middleware.TenantContext's X-Tenant-ID gate: the authz wildcard "*" only —
// tenant.manage is sufficient for same-tenant work but not to leave the tenant.
//
// ok=false means a response has already been written and the caller must
// return. Fail closed: no authz service, no identity, or a check error refuses.
func (h *Handler) resolveTenant(c *gin.Context) (int64, bool) {
	own := tenantctx.FromContext(c, h.tenantID)
	t := c.Query("tenant_id")
	if t == "" {
		return own, true
	}
	id, err := strconv.ParseInt(t, 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, errcode.NumBadRequest, "invalid tenant_id")
		return 0, false
	}
	if id == own {
		return own, true
	}
	svc := authz.FromContext(c)
	if svc == nil {
		response.Error(c, http.StatusInternalServerError, errcode.NumNotConfigured,
			"authz not installed", "")
		return 0, false
	}
	uid, _ := c.Get("user_id")
	userID, _ := uid.(int64)
	if userID == 0 {
		response.Unauthorized(c, errcode.NumUnauthenticated, "not authenticated")
		return 0, false
	}
	// Check against the caller's OWN tenant: bindings live there, and asking in
	// the target tenant would evaluate the escape inside the place being escaped
	// into.
	ok, err := svc.Check(c.Request.Context(), sessionTenant(c, own), userID, "*", nil)
	if err != nil || !ok {
		response.Forbidden(c, errcode.NumForbidden, "cross-tenant drilldown requires super_admin")
		return 0, false
	}
	return id, true
}

// sessionTenant is the tenant the caller's session was issued for, which
// middleware.TenantContext preserves separately when it honours an
// X-Tenant-ID override. Falls back to the effective tenant.
func sessionTenant(c *gin.Context, fallback int64) int64 {
	if v, ok := c.Get("session_tenant_id"); ok {
		if id, ok := v.(int64); ok && id > 0 {
			return id
		}
	}
	return fallback
}

func statusLabel(s int) string {
	if s == 1 {
		return "success"
	}
	return "fail"
}

func resourceIDStr(id *int64) string {
	if id == nil {
		return ""
	}
	return itoa(*id)
}

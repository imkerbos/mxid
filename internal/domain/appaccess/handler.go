package appaccess

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// SubjectResolver resolves a (type, id) pair to a display name + code so
// the console can render policy rows without N+1 lookups in the UI.
// Injected at wire time from main.go.
type SubjectResolver interface {
	Resolve(ctx *gin.Context, subjectType string, id int64) (name, code string)
}

type Handler struct {
	service    *Service
	resolver   SubjectResolver
	defaultTID int64
}

func NewHandler(svc *Service, r SubjectResolver, defaultTID int64) *Handler {
	return &Handler{service: svc, resolver: r, defaultTID: defaultTID}
}

func (h *Handler) Register(rg *gin.RouterGroup) {
	app := rg.Group("/apps/:id/access-policies")
	{
		app.GET("", authz.Require("app.read", nil), h.listForApp)
		app.POST("", authz.Require("app.access.manage", nil), h.createForApp)
		app.POST("/batch", authz.Require("app.access.manage", nil), h.batchForApp)
		app.DELETE("/:policy_id", authz.Require("app.access.manage", nil), h.remove)
	}
	grp := rg.Group("/app-groups/:id/access-policies")
	{
		grp.GET("", authz.Require("app.read", nil), h.listForAppGroup)
		grp.POST("", authz.Require("app.access.manage", nil), h.createForAppGroup)
		grp.POST("/batch", authz.Require("app.access.manage", nil), h.batchForAppGroup)
		grp.DELETE("/:policy_id", authz.Require("app.access.manage", nil), h.remove)
	}
}

func (h *Handler) tenantID(c *gin.Context) int64 {
	return tenantctx.FromContext(c, h.defaultTID)
}

func (h *Handler) userID(c *gin.Context) *int64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(int64); ok {
			return &id
		}
	}
	return nil
}

/* ──────────────── App-scoped endpoints ──────────────── */

func (h *Handler) listForApp(c *gin.Context) {
	appID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	rows, err := h.service.ListOwnByApp(c.Request.Context(), appID, h.tenantID(c))
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, h.toViews(c, rows))
}

func (h *Handler) createForApp(c *gin.Context) {
	appID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body createBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	p, err := h.service.AddPolicy(c.Request.Context(), AddPolicyRequest{
		AppID:       &appID,
		TenantID:    h.tenantID(c),
		SubjectType: body.SubjectType,
		SubjectID:   body.SubjectID,
		Effect:      body.Effect,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, p)
}

/* ──────────────── App-group-scoped endpoints ──────────────── */

func (h *Handler) listForAppGroup(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	rows, err := h.service.ListByAppGroup(c.Request.Context(), groupID, h.tenantID(c))
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, h.toViews(c, rows))
}

func (h *Handler) createForAppGroup(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body createBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	p, err := h.service.AddPolicy(c.Request.Context(), AddPolicyRequest{
		AppGroupID:  &groupID,
		TenantID:    h.tenantID(c),
		SubjectType: body.SubjectType,
		SubjectID:   body.SubjectID,
		Effect:      body.Effect,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, p)
}

/* ──────────────── Batch endpoints ──────────────── */

// batchBody adds one subject_type + effect for many subjects at once. Ids are
// JSON strings (snowflake ids exceed JS's safe-integer range) and parsed here.
type batchBody struct {
	SubjectType string   `json:"subject_type" binding:"required"`
	SubjectIDs  []string `json:"subject_ids" binding:"required"`
	Effect      string   `json:"effect"`
}

func (h *Handler) batchForApp(c *gin.Context) {
	appID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	h.batch(c, &appID, nil)
}

func (h *Handler) batchForAppGroup(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	h.batch(c, nil, &groupID)
}

func (h *Handler) batch(c *gin.Context, appID, groupID *int64) {
	var body batchBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	ids := make([]int64, 0, len(body.SubjectIDs))
	for _, s := range body.SubjectIDs {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id == 0 {
			response.BadRequest(c, 40002, "invalid subject_id")
			return
		}
		ids = append(ids, id)
	}
	res, err := h.service.AddPoliciesBatch(c.Request.Context(), BatchAddRequest{
		AppID:       appID,
		AppGroupID:  groupID,
		TenantID:    h.tenantID(c),
		SubjectType: body.SubjectType,
		SubjectIDs:  ids,
		Effect:      body.Effect,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, gin.H{"created": len(res.Created), "skipped": res.Skipped})
}

/* ──────────────── Common ──────────────── */

type createBody struct {
	SubjectType string `json:"subject_type" binding:"required"`
	SubjectID   int64  `json:"subject_id,string"`
	Effect      string `json:"effect"`
}

func (h *Handler) remove(c *gin.Context) {
	policyID, ok := ginutil.ParseInt64Param(c, "policy_id")
	if !ok {
		return
	}
	if err := h.service.DeletePolicy(c.Request.Context(), policyID, h.tenantID(c)); err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func (h *Handler) toViews(c *gin.Context, rows []*Policy) []*PolicyView {
	views := make([]*PolicyView, 0, len(rows))
	for _, p := range rows {
		v := &PolicyView{Policy: p}
		if h.resolver != nil && p.SubjectType != SubjectPublic {
			v.SubjectName, v.SubjectCode = h.resolver.Resolve(c, p.SubjectType, p.SubjectID)
		}
		views = append(views, v)
	}
	return views
}

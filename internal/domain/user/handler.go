package user

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/errcode"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/idstr"
	"github.com/imkerbos/mxid/pkg/pagination"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler handles HTTP requests for the user domain.
type Handler struct {
	svc *Service
	// stepUpFresh reports whether the caller's console session passed MFA
	// recently enough. Injected because the batch route carries an action in
	// its body, so the route-level step-up middleware — which sees only method
	// and path — cannot tell a bulk delete from a bulk enable. nil disables the
	// check, which is why BatchAction refuses a delete when it is unset.
	stepUpFresh func(c *gin.Context, tenantID int64) bool
}

// NewHandler creates a new user handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// SetStepUpFresh injects the step-up freshness check. Wired in app.Run once the
// step-up dependencies exist, which is after this module is constructed.
func (h *Handler) SetStepUpFresh(fn func(c *gin.Context, tenantID int64) bool) {
	h.stepUpFresh = fn
}

// RegisterRoutes registers user routes on the given router group.
//
// Permission enforcement: every write route is gated by an authz.Require —
// the perm code follows the dot.case catalog seeded by migration 000016.
// Scope is intentionally global on user-resource endpoints because the
// scoping that matters happens elsewhere:
//
//   - "user.org.assign" gates POST /orgs/:id/members (org-scoped)
//   - "user.group.assign" gates POST /groups/:id/members (group-scoped)
//
// So a dept_admin can hold user.{create,update,...} globally without being
// able to actually plant the user in a foreign part of the tree — they
// fail at the org-membership endpoint instead.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	users := rg.Group("/users")
	{
		users.GET("", authz.Require("user.read", nil), h.List)
		users.POST("", authz.Require("user.create", nil), h.Create)
		users.POST("/batch", authz.Require("user.update", nil), h.BatchAction)
		users.GET("/:id", authz.Require("user.read", nil), h.Get)
		users.PUT("/:id", authz.Require("user.update", nil), h.Update)
		users.DELETE("/:id", authz.Require("user.delete", nil), h.Delete)
		// Restore undoes a soft delete. It does NOT restore identity bindings —
		// that is a separate, separately-audited decision on the identities
		// endpoint below. Gated by its own catalog permission (user.restore,
		// see migration 000069) rather than reusing user.delete: delete and
		// restore are separate capabilities, the same way user.lock and
		// user.unlock already are, so a tenant can grant "can undo a
		// deletion" without also granting "can delete".
		users.POST("/:id/restore", authz.Require("user.restore", nil), h.RestoreUser)
		users.PUT("/:id/status", authz.Require("user.update", nil), h.UpdateStatus)
		users.POST("/:id/lock", authz.Require("user.lock", nil), h.LockUser)
		users.POST("/:id/unlock", authz.Require("user.unlock", nil), h.UnlockUser)
		users.PUT("/:id/password", authz.Require("user.reset_password", nil), h.ResetPassword)
		// Note: super-admin is managed via the Super Admin role's members
		// (POST/DELETE /roles/:id/members), which the permission service maps to
		// the is_super_admin flag. There is no direct per-user toggle endpoint.

		users.GET("/:id/detail", authz.Require("user.read", nil), h.GetDetail)
		users.PUT("/:id/detail", authz.Require("user.update", nil), h.UpdateDetail)

		users.GET("/:id/identities", authz.Require("user.read", nil), h.ListIdentities)
		users.DELETE("/:id/identities/:iid", authz.Require("user.identity.manage", nil), h.UnbindIdentity)
		users.GET("/:id/identities/deleted", authz.Require("user.read", nil), h.ListDeletedIdentities)
		users.POST("/:id/identities/:iid/restore", authz.Require("user.identity.manage", nil), h.RestoreIdentity)

		users.GET("/:id/mfa", authz.Require("user.read", nil), h.ListMFA)
		users.DELETE("/:id/mfa/:type", authz.Require("user.mfa.manage", nil), h.DeleteMFA)
		users.POST("/:id/mfa/lockout/clear", authz.Require("user.mfa.manage", nil), h.ClearMFALockout)

		users.GET("/:id/login-history", authz.Require("user.login_history.read", nil), h.ListLoginHistory)
	}
}

// ListLoginHistory handles GET /users/:id/login-history. Paginated, newest first.
func (h *Handler) ListLoginHistory(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	p := pagination.Parse(c)
	rows, total, err := h.svc.ListLoginRecords(c.Request.Context(), id, p.Page, p.PageSize)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.Paginated(c, rows, total, p.Page, p.PageSize)
}

// getTenantID extracts the effective tenant ID from gin.Context. Reads the
// value set by middleware.TenantContext (super_admin override) or the
// session-derived tenant_id from authn middleware. Falls back to 1 for
// single-tenant dev mode.
// Hardcoded to 1 for MVP.
func getTenantID(c *gin.Context) int64 {
	return tenantctx.FromContext(c, 1)
}

// Create handles POST /users.
func (h *Handler) Create(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}

	tenantID := getTenantID(c)
	user, err := h.svc.Create(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	detail, _ := h.svc.GetDetail(c.Request.Context(), user.ID)
	response.Created(c, ToResponse(user, detail))
}

// Get handles GET /users/:id.
//
// Returns the full PII bundle (phone / email / detail) so the admin edit
// form can render the current values. Reads of someone else's record
// emit a UserPIIView audit event so the access trail is queryable. Self-
// reads (caller looking at their own row) are NOT audited because admins
// will see their own row in normal navigation and we don't want to flood
// the audit log.
func (h *Handler) Get(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	user, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	detail, _ := h.svc.GetDetail(c.Request.Context(), user.ID)

	if actorID, ok := authn.GetUserID(c); ok && actorID != id {
		h.svc.RecordPIIView(
			c.Request.Context(),
			actorID,
			getTenantID(c),
			id,
			[]string{"phone", "email", "detail"},
		)
	}

	response.OK(c, ToResponse(user, detail))
}

// Update handles PUT /users/:id.
func (h *Handler) Update(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}

	tenantID := getTenantID(c)
	user, err := h.svc.Update(c.Request.Context(), id, tenantID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	detail, _ := h.svc.GetDetail(c.Request.Context(), user.ID)
	response.OK(c, ToResponse(user, detail))
}

// Delete handles DELETE /users/:id.
func (h *Handler) Delete(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// RestoreUser handles POST /users/:id/restore.
func (h *Handler) RestoreUser(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.svc.RestoreUser(c.Request.Context(), id); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}

// List handles GET /users.
func (h *Handler) List(c *gin.Context) {
	tenantID := getTenantID(c)
	p := pagination.Parse(c)

	var req ListUsersRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}

	params := ListParams{
		Page:           p.Page,
		PageSize:       p.PageSize,
		Search:         req.Search,
		Status:         req.Status,
		OrgID:          req.OrgID,
		IncludeDeleted: req.IncludeDeleted,
	}

	users, total, err := h.svc.List(c.Request.Context(), tenantID, params)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	// List view: mask PII. Detail page calls /users/:id which returns the
	// raw fields for admin editing.
	items := make([]*UserResponse, len(users))
	ids := make([]int64, len(users))
	for i, u := range users {
		items[i] = ToResponseMasked(u)
		ids[i] = u.ID
	}

	// Batch the MFA-enabled flag for the whole page (one GROUP BY, no N+1) so
	// the list can show an MFA badge. A lookup failure must not fail the list —
	// the badge just stays off.
	if mfaSet, err := h.svc.MFAEnabledByUserIDs(c.Request.Context(), ids); err == nil {
		for _, it := range items {
			it.MFAEnabled = mfaSet[it.ID]
		}
	}

	response.Paginated(c, items, total, p.Page, p.PageSize)
}

// UpdateStatus handles PUT /users/:id/status.
func (h *Handler) UpdateStatus(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}

	if err := h.svc.UpdateStatus(c.Request.Context(), id, req.Status); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// ResetPassword handles PUT /users/:id/password.
func (h *Handler) ResetPassword(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}

	if err := h.svc.ResetPassword(c.Request.Context(), id, &req); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// callerMay evaluates a permission for the current caller outside the route
// middleware, for a route whose required permission depends on the request
// body. Fails closed: no authz service, no user, or a check error is a denial.
func (h *Handler) callerMay(c *gin.Context, perm string) bool {
	svc := authz.FromContext(c)
	if svc == nil {
		return false
	}
	uid := actorIDFromCtx(c)
	if uid == 0 {
		return false
	}
	ok, err := svc.Check(c.Request.Context(), tenantctx.FromContext(c, 0), uid, perm, nil)
	return err == nil && ok
}

// BatchAction handles POST /users/batch. Applies enable/disable/delete to
// a list of user IDs. Returns a per-id error map so the console UI can
// show partial success.
func (h *Handler) BatchAction(c *gin.Context) {
	var req BatchUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}
	ids, err := idstr.ParseList(req.IDs)
	if err != nil {
		// Malformed id list is a bad request body, not a service error. 40001
		// (not 40003) — 40003 collides with the frontend's global
		// totpCodeReused localization and would misrender the message.
		response.BadRequest(c, errcode.NumBadRequest, "invalid user id list")
		return
	}
	// A batch delete is a delete. The route is mounted with user.update because
	// that is the floor for enable/disable, but BatchActionDelete reaches the
	// same Service.Delete as DELETE /users/:id — which requires user.delete and
	// a fresh step-up. Without these two checks the batch endpoint is a way
	// around both: an operator holding only user.update, with no recent MFA,
	// could delete users in bulk.
	if req.Action == BatchActionDelete {
		if !h.callerMay(c, "user.delete") {
			response.Forbidden(c, errcode.NumForbidden, "user.delete required to delete users")
			return
		}
		tenantID := tenantctx.FromContext(c, 0)
		if h.stepUpFresh == nil || !h.stepUpFresh(c, tenantID) {
			response.Forbidden(c, authn.CodeStepUpRequired, "step-up mfa required for this operation")
			return
		}
	}

	res, err := h.svc.BatchAction(c.Request.Context(), ids, req.Action, actorIDFromCtx(c))
	if err != nil {
		response.BadRequest(c, errcode.NumInvalidInput, err.Error())
		return
	}
	response.OK(c, res)
}

// LockUser handles POST /users/:id/lock. Admin operation; reason is required
// for audit purposes.
func (h *Handler) LockUser(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var req LockUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}
	actorID := actorIDFromCtx(c)
	if err := h.svc.LockUser(c.Request.Context(), id, req.Reason, actorID); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}

// UnlockUser handles POST /users/:id/unlock. Admin operation.
func (h *Handler) UnlockUser(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	actorID := actorIDFromCtx(c)
	if err := h.svc.UnlockUser(c.Request.Context(), id, actorID); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}

// actorIDFromCtx extracts the calling admin's user ID from the gin context.
// Returns 0 if no auth context is attached (which should not happen for
// console routes guarded by AuthMiddleware, but stays safe).
func actorIDFromCtx(c *gin.Context) int64 {
	v, ok := c.Get("user_id")
	if !ok {
		return 0
	}
	if id, ok := v.(int64); ok {
		return id
	}
	return 0
}

// ListIdentities handles GET /users/:id/identities.
func (h *Handler) ListIdentities(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	identities, err := h.svc.ListIdentities(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]*UserIdentityResponse, len(identities))
	for i, idt := range identities {
		items[i] = ToIdentityResponse(idt)
	}
	response.OK(c, items)
}

// UnbindIdentity handles DELETE /users/:id/identities/:iid. Admin operation;
// removes the third-party binding so the user must re-link from the portal.
func (h *Handler) UnbindIdentity(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	iidStr := c.Param("iid")
	iid, err := strconv.ParseInt(iidStr, 10, 64)
	if err != nil {
		response.BadRequest(c, errcode.NumInvalidInput, "invalid identity id")
		return
	}

	if err := h.svc.UnbindIdentity(c.Request.Context(), id, iid); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}

// ListDeletedIdentities handles GET /users/:id/identities/deleted. Feeds the
// console's "unbound" section so a mis-clicked unbind can be undone.
func (h *Handler) ListDeletedIdentities(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	items, err := h.svc.ListDeletedIdentities(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	out := make([]*UserIdentityResponse, len(items))
	for i, idt := range items {
		out[i] = ToIdentityResponse(idt)
	}
	response.OK(c, out)
}

// RestoreIdentity handles POST /users/:id/identities/:iid/restore.
func (h *Handler) RestoreIdentity(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	iid, err := strconv.ParseInt(c.Param("iid"), 10, 64)
	if err != nil {
		response.BadRequest(c, errcode.NumInvalidInput, "invalid identity id")
		return
	}
	if err := h.svc.RestoreIdentity(c.Request.Context(), id, iid); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}

// GetDetail handles GET /users/:id/detail.
func (h *Handler) GetDetail(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	detail, err := h.svc.GetDetail(c.Request.Context(), id)
	if err != nil {
		// Missing detail row is not an error here — return an empty payload
		// so the frontend form binds against `null` consistently.
		if errors.Is(err, ErrDetailNotFound) {
			response.OK(c, &UserDetailResponse{})
			return
		}
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, &UserDetailResponse{
		Gender:     detail.Gender,
		Birthday:   detail.Birthday,
		Address:    detail.Address,
		EmployeeNo: detail.EmployeeNo,
		JobTitle:   detail.JobTitle,
		Department: detail.Department,
		Extra:      detail.Extra,
	})
}

// UpdateDetail handles PUT /users/:id/detail. Upserts the detail row using
// patch semantics — only fields present in the request body are touched.
func (h *Handler) UpdateDetail(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var req UpdateDetailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, errcode.NumBadRequest, "invalid request body")
		return
	}
	detail, err := h.svc.UpsertDetail(c.Request.Context(), id, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, &UserDetailResponse{
		Gender:     detail.Gender,
		Birthday:   detail.Birthday,
		Address:    detail.Address,
		EmployeeNo: detail.EmployeeNo,
		JobTitle:   detail.JobTitle,
		Department: detail.Department,
		Extra:      detail.Extra,
	})
}

// ListMFA handles GET /users/:id/mfa. Returns metadata about each enrolled
// factor; secret material is never serialised.
func (h *Handler) ListMFA(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	mfas, err := h.svc.ListMFA(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	items := make([]*UserMFAResponse, len(mfas))
	for i, m := range mfas {
		items[i] = &UserMFAResponse{
			Type:      m.Type,
			IsDefault: m.IsDefault,
			Verified:  m.Verified,
			CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: m.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	response.OK(c, items)
}

// DeleteMFA handles DELETE /users/:id/mfa/:type. Admin force-unenroll of a
// specific factor (e.g. "totp"). The next login will skip the MFA challenge
// if no other verified factor remains.
func (h *Handler) DeleteMFA(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	mfaType := c.Param("type")
	if mfaType == "" {
		response.BadRequest(c, errcode.NumInvalidInput, "missing mfa type")
		return
	}
	if err := h.svc.DeleteMFA(c.Request.Context(), id, mfaType); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}

// ClearMFALockout handles POST /users/:id/mfa/lockout/clear. Admin op
// that wipes the per-user MFA fail counters + lock keys so the user can
// retry immediately (e.g. after a fat-fingering streak hit the threshold).
func (h *Handler) ClearMFALockout(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	h.svc.ClearMFALockout(c.Request.Context(), id)
	response.OK(c, gin.H{"cleared": true})
}

// handleServiceError maps service errors to HTTP responses.
// handleServiceError maps a domain error to its response via the errcode
// registry (see errcodes.go for the user-domain bindings).
func (h *Handler) handleServiceError(c *gin.Context, err error) {
	response.MapError(c, err)
}

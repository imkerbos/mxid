package authz

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/errcode"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// AdministerTargetDenial decides whether the caller may administer another
// user, returning the refusal reason or "" when allowed.
//
// A route-level Require only asks what the CALLER holds; nothing looks at the
// target. The seeded user_manager role holds the user-desk permissions
// globally, so without this check it could strip the super_admin's TOTP, reset
// its password, disable it, revoke its sessions or offboard it — privilege
// escalation (or a tenant-wide denial of service) from a user-desk role.
//
// Rule, same semantics as the role-grant path (permission.checkAssignAllowed):
// you may not administer a user whose effective permissions are not a subset of
// your own, and only a wildcard holder (super_admin) may administer another
// wildcard holder.
//
// Lives here rather than in a domain package because the authz engine arrives
// through the gin context (FromContext) and several domains need the same
// decision; a domain home would force an import cycle on at least one of them.
//
// Fails closed on every unknown: no engine, no caller identity, failed lookup.
func AdministerTargetDenial(c *gin.Context, targetID int64) string {
	deny := func(msg string) string { return msg }
	svc := FromContext(c)
	if svc == nil {
		return deny("authz engine unavailable")
	}
	callerID := userIDFromCtx(c)
	if callerID == 0 {
		return deny("caller not authenticated")
	}
	// Acting on yourself cannot be an escalation.
	if callerID == targetID {
		return ""
	}
	tenantID := tenantctx.FromContext(c, 0)
	callerPerms, err := svc.PermissionsForUser(c.Request.Context(), tenantID, callerID)
	if err != nil {
		return deny("caller permission lookup failed")
	}
	// Wildcard caller (super_admin) keeps full reach, including over peers.
	if _, ok := callerPerms["*"]; ok {
		return ""
	}
	targetPerms, err := svc.PermissionsForUser(c.Request.Context(), tenantID, targetID)
	if err != nil {
		return deny("target permission lookup failed")
	}
	if _, ok := targetPerms["*"]; ok {
		return deny("only a super admin can administer a super admin")
	}
	for p := range targetPerms {
		if _, ok := callerPerms[p]; !ok {
			// The missing code stays out of the message: it would tell a prober
			// which privilege to go after next.
			return deny("target holds privileges beyond your own")
		}
	}
	return ""
}

// MayAdministerTarget is AdministerTargetDenial with the 403 written for the
// single-operation routes. Reports false once it has responded.
func MayAdministerTarget(c *gin.Context, targetID int64) bool {
	if reason := AdministerTargetDenial(c, targetID); reason != "" {
		response.Forbidden(c, errcode.NumForbiddenScope, reason)
		return false
	}
	return true
}

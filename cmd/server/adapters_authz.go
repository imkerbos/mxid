package main

// authz / permission adapters. Bridge the authz engine to the permission
// domain + group / org membership lookups.

import (
	"context"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/group"
	"github.com/imkerbos/mxid/internal/domain/org"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/event"
)

type permissionGroupLookupAdapter struct{ groupModule *group.Module }

func newPermissionGroupLookupAdapter(groupModule *group.Module) *permissionGroupLookupAdapter {
	return &permissionGroupLookupAdapter{groupModule: groupModule}
}

func (a *permissionGroupLookupAdapter) GroupIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error) {
	groups, err := a.groupModule.Repo.ListByUserID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids, nil
}

type permissionOrgLookupAdapter struct{ orgModule *org.Module }

func newPermissionOrgLookupAdapter(orgModule *org.Module) *permissionOrgLookupAdapter {
	return &permissionOrgLookupAdapter{orgModule: orgModule}
}

func (a *permissionOrgLookupAdapter) AncestorIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error) {
	return a.orgModule.Service.AncestorIDsForUser(ctx, tenantID, userID)
}

type authzBindingProvider struct {
	app         *bootstrap.App
	permModule  *permission.Module
	groupModule *group.Module
	orgModule   *org.Module
}

func newAuthzBindingProvider(app *bootstrap.App, perm *permission.Module, grp *group.Module, organ *org.Module) *authzBindingProvider {
	return &authzBindingProvider{app: app, permModule: perm, groupModule: grp, orgModule: organ}
}

// EffectiveBindingsForUser unions direct/group/org bindings + pre-joins
// permission codes so the authz engine answers Check() in O(bindings).
//
// Super-admin path: read `mxid_user.is_super_admin` directly and synthesize
// a single global wildcard binding. Migration 000033 backfills this column
// from the legacy "binding to role_id=1" convention, so we no longer rely
// on a magic role ID surviving data import / restore.
func (a *authzBindingProvider) EffectiveBindingsForUser(ctx context.Context, tenantID, userID int64) ([]authz.EffectiveBinding, error) {
	var superAdmin struct {
		IsSuperAdmin bool
	}
	if err := a.app.DB.WithContext(ctx).
		Table("mxid_user").
		Select("is_super_admin").
		Where("id = ? AND tenant_id = ? AND deleted_at IS NULL", userID, tenantID).
		Scan(&superAdmin).Error; err != nil {
		return nil, err
	}
	if superAdmin.IsSuperAdmin {
		return []authz.EffectiveBinding{{
			RoleID:      0,
			Permissions: map[string]struct{}{"*": {}},
			Source:      "super_admin",
			SourceID:    userID,
		}}, nil
	}

	groups, _ := a.groupModule.Repo.ListByUserID(ctx, tenantID, userID)
	groupIDs := make([]int64, len(groups))
	for i, g := range groups {
		groupIDs[i] = g.ID
	}
	orgIDs, _ := a.orgModule.Service.AncestorIDsForUser(ctx, tenantID, userID)

	type row struct {
		RoleID    int64
		ScopeType *string
		ScopeID   *int64
		Source    string
		SourceID  int64
	}
	var rows []row
	q := a.app.DB.WithContext(ctx).
		Table("mxid_role_binding b").
		Joins("INNER JOIN mxid_role r ON r.id = b.role_id AND r.tenant_id = ? AND r.deleted_at IS NULL", tenantID).
		Select(`DISTINCT b.role_id, b.scope_type, b.scope_id,
			CASE b.subject_type WHEN 'user' THEN 'direct' WHEN 'group' THEN 'group' WHEN 'org' THEN 'org' ELSE 'direct' END AS source,
			b.subject_id AS source_id`).
		Where("(b.subject_type = 'user' AND b.subject_id = ?)", userID)
	if len(groupIDs) > 0 {
		q = q.Or("b.subject_type = 'group' AND b.subject_id IN ?", groupIDs)
	}
	if len(orgIDs) > 0 {
		q = q.Or("b.subject_type = 'org' AND b.subject_id IN ?", orgIDs)
	}
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	// Pre-join role_permission to fill Permissions set.
	roleSet := map[int64]struct{}{}
	for _, r := range rows {
		roleSet[r.RoleID] = struct{}{}
	}
	roleIDs := make([]int64, 0, len(roleSet))
	for id := range roleSet {
		roleIDs = append(roleIDs, id)
	}
	type permRow struct {
		RoleID         int64
		PermissionCode string
	}
	var permRows []permRow
	_ = a.app.DB.WithContext(ctx).
		Table("mxid_role_permission rp").
		Joins("INNER JOIN mxid_permission p ON p.id = rp.permission_id").
		Select("rp.role_id, p.code AS permission_code").
		Where("rp.role_id IN ?", roleIDs).Scan(&permRows).Error
	codesByRole := map[int64]map[string]struct{}{}
	for _, p := range permRows {
		if codesByRole[p.RoleID] == nil {
			codesByRole[p.RoleID] = map[string]struct{}{}
		}
		codesByRole[p.RoleID][p.PermissionCode] = struct{}{}
	}
	out := make([]authz.EffectiveBinding, 0, len(rows))
	for _, r := range rows {
		perms := codesByRole[r.RoleID]
		if perms == nil {
			perms = map[string]struct{}{}
		}
		eb := authz.EffectiveBinding{
			RoleID: r.RoleID, Permissions: perms,
			Source: r.Source, SourceID: r.SourceID,
		}
		if r.ScopeType != nil {
			eb.ScopeType = authz.ScopeKind(*r.ScopeType)
		}
		if r.ScopeID != nil {
			eb.ScopeID = *r.ScopeID
		}
		out = append(out, eb)
	}
	return out, nil
}

type authzOrgAncestry struct{ orgModule *org.Module }

func newAuthzOrgAncestry(orgModule *org.Module) *authzOrgAncestry {
	return &authzOrgAncestry{orgModule: orgModule}
}

func (a *authzOrgAncestry) IsAncestorOrSelf(ctx context.Context, ancestor, descendant int64) (bool, error) {
	return a.orgModule.Service.IsAncestorOrSelf(ctx, ancestor, descendant)
}

// wireAuthzCacheInvalidation subscribes the authz cache to the in-process
// event bus so any mutation that changes effective bindings clears the
// affected user's cache entry. The pub/sub channel inside the cache then
// broadcasts the invalidation to peer pods.
//
// Granularity:
//   - permission/role mutations that touch the role itself or its
//     permission set affect every user holding that role → InvalidateAll.
//   - role-member changes (add/remove) typically carry the affected user
//     ID in the event payload → targeted Invalidate.
//   - user / org / group mutations that re-shape inheritance trigger a
//     broad InvalidateAll for safety; finer-grained invalidation can be
//     wired later once payload shapes are normalized.
//
// Coarser invalidation has only the cost of a one-time DB hit on the
// next request from each affected user — well under the cost of leaking
// removed permissions for the L2 TTL window.
func wireAuthzCacheInvalidation(a *bootstrap.App, cache *authz.CachedBindingProvider) {
	if a == nil || cache == nil || a.EventBus == nil {
		return
	}

	invalidateAll := func(_ context.Context, _ event.Event) {
		_ = cache.InvalidateAll(context.Background())
	}
	invalidateUserFromPayload := func(_ context.Context, evt event.Event) {
		p, ok := evt.Payload.(map[string]any)
		if !ok {
			_ = cache.InvalidateAll(context.Background())
			return
		}
		tenantID, _ := p["tenant_id"].(int64)
		userID, _ := p["user_id"].(int64)
		if userID == 0 {
			_ = cache.InvalidateAll(context.Background())
			return
		}
		_ = cache.Invalidate(context.Background(), tenantID, userID)
	}

	// Role-level changes affect every user holding the role.
	for _, t := range []string{
		permission.RoleCreated,
		permission.RoleUpdated,
		permission.RoleDeleted,
		permission.RolePermissionsSet,
	} {
		a.EventBus.Subscribe(t, invalidateAll)
	}

	// Member additions / removals carry a user_id when subject_type=user.
	// Group / org subjects fall back to InvalidateAll inside the handler.
	a.EventBus.Subscribe(permission.RoleMemberAdded, invalidateUserFromPayload)
	a.EventBus.Subscribe(permission.RoleMemberRemoved, invalidateUserFromPayload)

	// Group membership changes affect group-inherited bindings; payload
	// carries the user_id so we can do a targeted Invalidate.
	a.EventBus.Subscribe(event.GroupMemberAdded, invalidateUserFromPayload)
	a.EventBus.Subscribe(event.GroupMemberRemoved, invalidateUserFromPayload)

	// Org structural moves: a user changing org changes which org-scope
	// bindings they inherit. user_id is in payload when known.
	a.EventBus.Subscribe(event.OrgMemberMoved, invalidateUserFromPayload)

	// Super-admin flip uses the "target_id" key (not user_id, which is
	// the actor). Translate before invalidating.
	invalidateTargetFromPayload := func(_ context.Context, evt event.Event) {
		p, ok := evt.Payload.(map[string]any)
		if !ok {
			_ = cache.InvalidateAll(context.Background())
			return
		}
		tenantID, _ := p["tenant_id"].(int64)
		targetID, _ := p["target_id"].(int64)
		if targetID == 0 {
			_ = cache.InvalidateAll(context.Background())
			return
		}
		_ = cache.Invalidate(context.Background(), tenantID, targetID)
	}
	a.EventBus.Subscribe(event.UserSuperAdminGrant, invalidateTargetFromPayload)
	a.EventBus.Subscribe(event.UserSuperAdminRevoke, invalidateTargetFromPayload)

	// User lifecycle: status flips, super-admin toggles, deletions all
	// reshape what the cache knows about that user.
	for _, t := range []string{
		event.UserUpdated,
		event.UserLocked,
		event.UserUnlocked,
		event.UserDeleted,
	} {
		a.EventBus.Subscribe(t, invalidateUserFromPayload)
	}

	// Org / group structural changes can move a user across inherited
	// bindings. Cheaper than threading user IDs through every reshape.
	for _, t := range []string{
		event.OrgUpdated,
		event.OrgDeleted,
	} {
		a.EventBus.Subscribe(t, invalidateAll)
	}
}

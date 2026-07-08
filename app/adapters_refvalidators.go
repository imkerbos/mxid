package app

// Referenced-entity tenant validators (Phase 2.6).
//
// Association handlers take a referenced entity id (user / group / org / role /
// app / app-group) from the REQUEST BODY and link it to a tenant-owned parent.
// The parent is tenant-guarded, but the REFERENCED entity was not validated —
// so an admin could plant a FOREIGN-tenant entity into their own parent,
// granting it the parent's scoped access.
//
// Each validator below is backed by the referent's TENANT-SCOPED repo GetByID.
// The tenantscope gorm plugin appends tenant_id=? to the query, so a
// cross-tenant id resolves to gorm.ErrRecordNotFound → the validator returns
// (false, nil) and the calling service rejects the association. A genuine DB
// error propagates as (false, err) and fails the request closed.
//
// These are injected via the per-service Set*Validator(s) setters in main.go,
// keeping each domain free of cross-domain imports.

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/group"
	"github.com/imkerbos/mxid/internal/domain/org"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/internal/domain/user"
)

// existsInTenant wraps a tenant-scoped GetByID into an existence predicate.
// not-found (cross-tenant id) → (false, nil); other errors propagate.
func existsInTenant[T any](getByID func(ctx context.Context, id int64) (T, error)) func(ctx context.Context, id int64) (bool, error) {
	return func(ctx context.Context, id int64) (bool, error) {
		if _, err := getByID(ctx, id); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
}

// validateUserInTenant returns a tenant-scoped user existence predicate.
func validateUserInTenant(m *user.Module) func(ctx context.Context, id int64) (bool, error) {
	return existsInTenant(m.Repo.GetByID)
}

// validateGroupInTenant returns a tenant-scoped user-group existence predicate.
func validateGroupInTenant(m *group.Module) func(ctx context.Context, id int64) (bool, error) {
	return existsInTenant(m.Repo.GetByID)
}

// validateOrgInTenant returns a tenant-scoped organization existence predicate.
func validateOrgInTenant(m *org.Module) func(ctx context.Context, id int64) (bool, error) {
	return existsInTenant(m.Repo.GetByID)
}

// validateRoleInTenant returns a tenant-scoped role existence predicate
// (mxid_role; tenantscope-plugin filtered).
func validateRoleInTenant(m *permission.Module) func(ctx context.Context, id int64) (bool, error) {
	return existsInTenant(m.Repo.GetRoleByID)
}

// validateAppInTenant returns a tenant-scoped app existence predicate. Note
// mxid_app's predicate is tenant_id=? OR NULL, so shared/global apps are
// reachable by design — a foreign PRIVATE app still resolves to not-found.
func validateAppInTenant(m *app.Module) func(ctx context.Context, id int64) (bool, error) {
	return existsInTenant(m.Repo.GetByID)
}

// validateAppGroupInTenant returns a tenant-scoped app-group existence predicate.
func validateAppGroupInTenant(m *app.Module) func(ctx context.Context, id int64) (bool, error) {
	return existsInTenant(m.Repo.GetGroupByID)
}

// --- Subject name resolvers (role-member display) -------------------------
//
// These batch-resolve a role binding's subject id → a human-readable name so
// the permissions console shows "who" instead of a raw snowflake id. Backed by
// the same tenant-scoped repo GetByID as the validators (cross-tenant / deleted
// ids resolve to not-found and are simply omitted → caller keeps the id
// fallback). Injected via permission.Service.SetSubjectResolvers, keeping the
// permission domain free of user/group/org imports.

// resolveByID adapts a per-id tenant-scoped GetByID into the batch
// SubjectNameResolver shape. Ids that don't resolve (not-found) are skipped;
// a genuine DB error aborts the batch (the service treats that as non-fatal and
// falls back to ids for the whole page).
func resolveByID[T any](
	getByID func(ctx context.Context, id int64) (T, error),
	info func(T) permission.SubjectInfo,
) permission.SubjectNameResolver {
	return func(ctx context.Context, ids []int64) (map[int64]permission.SubjectInfo, error) {
		out := make(map[int64]permission.SubjectInfo, len(ids))
		for _, id := range ids {
			v, err := getByID(ctx, id)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					continue
				}
				return nil, err
			}
			out[id] = info(v)
		}
		return out, nil
	}
}

// deref returns *p or "" for a nil pointer — used to read optional string
// columns (display_name / email) without panicking.
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// superAdminManagerAdapter bridges the permission domain's super_admin role
// façade to the user domain's is_super_admin flag. Set delegates to the user
// service (which enforces tenant scope, idempotency, the last-super-admin guard
// and emits the grant/revoke audit event); List renders the member list.
type superAdminManagerAdapter struct{ userM *user.Module }

func (a superAdminManagerAdapter) SetSuperAdmin(ctx context.Context, actorID, tenantID, targetID int64, makeSuper bool) error {
	return a.userM.Service.SetSuperAdmin(ctx, actorID, tenantID, targetID, makeSuper)
}

func (a superAdminManagerAdapter) ListSuperAdmins(ctx context.Context, tenantID int64) ([]permission.SuperAdminInfo, error) {
	users, err := a.userM.Service.ListSuperAdmins(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]permission.SuperAdminInfo, len(users))
	for i, u := range users {
		name := deref(u.DisplayName)
		if name == "" {
			name = u.Username
		}
		out[i] = permission.SuperAdminInfo{UserID: u.ID, Name: name, Secondary: deref(u.Email)}
	}
	return out, nil
}

// subjectNameResolvers builds the user/group/org name resolvers for the
// permission member list.
func subjectNameResolvers(userM *user.Module, groupM *group.Module, orgM *org.Module) permission.SubjectResolvers {
	return permission.SubjectResolvers{
		User: resolveByID(userM.Repo.GetByID, func(u *user.User) permission.SubjectInfo {
			name := deref(u.DisplayName)
			if name == "" {
				name = u.Username
			}
			return permission.SubjectInfo{Name: name, Secondary: deref(u.Email)}
		}),
		Group: resolveByID(groupM.Repo.GetByID, func(g *group.UserGroup) permission.SubjectInfo {
			return permission.SubjectInfo{Name: g.Name}
		}),
		Org: resolveByID(orgM.Repo.GetByID, func(o *org.Organization) permission.SubjectInfo {
			return permission.SubjectInfo{Name: o.Name}
		}),
	}
}

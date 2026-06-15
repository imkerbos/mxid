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

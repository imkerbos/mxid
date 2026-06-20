package app

import (
	"context"

	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/offboarding"
)

// offboardFootprint bridges the appaccess + app services onto the offboarding
// AppFootprint interface, so an offboard can list every app the departing user
// could reach (for the review checklist) without the offboarding domain
// importing either service.
type offboardFootprint struct {
	access *appaccess.Service
	apps   *app.Service
}

// ForUser returns the user's authorized apps, denormalized into review refs.
// All apps are SSO (tier L1, access auto-cut by the offboard); the checklist
// still surfaces them so the admin can confirm any downstream local accounts.
func (f offboardFootprint) ForUser(ctx context.Context, userID, tenantID int64) ([]offboarding.AppRef, error) {
	ids, err := f.access.AppsForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	apps, err := f.apps.GetByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	refs := make([]offboarding.AppRef, 0, len(apps))
	for _, a := range apps {
		refs = append(refs, offboarding.AppRef{
			ID:   a.ID,
			Name: a.Name,
			Code: a.Code,
			Tier: offboarding.TierL1,
		})
	}
	return refs, nil
}

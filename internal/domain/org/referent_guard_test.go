package org

import (
	"context"
	"errors"
	"testing"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

func testIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return g
}

// tenantScopedUserValidator mimics the production validator: a referenced user
// id "exists" only when its owning tenant matches the caller's tenant context
// (exactly what the tenant-scoped repo GetByID resolves). userTenants maps
// userID -> owning tenantID.
func tenantScopedUserValidator(userTenants map[int64]int64) EntityValidator {
	return func(ctx context.Context, id int64) (bool, error) {
		owner, ok := userTenants[id]
		if !ok {
			return false, nil
		}
		s, _ := tenantscope.From(ctx)
		return owner == s.TenantID, nil
	}
}

// AddMember must reject a request-body user id that belongs to a different
// tenant — even though the parent org is owned by the caller — so a foreign
// user cannot be planted into the caller's org.
func TestService_AddMember_CrossTenantUserRejected(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db) // org 1 -> tenant 100, org 2 -> tenant 200

	// user 500 belongs to tenant 100; user 999 belongs to tenant 200.
	svc := &Service{
		repo:          NewRepository(db),
		idGen:         testIDGen(t),
		userValidator: tenantScopedUserValidator(map[int64]int64{500: 100, 999: 200}),
	}

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Caller (tenant 100) owns org 1. Planting foreign user 999 (tenant 200)
	// must be rejected.
	if err := svc.AddMember(ctxA, 1, &AddMemberRequest{UserID: 999}); !errors.Is(err, ErrUserNotInTenant) {
		t.Fatalf("AddMember foreign user: got %v want ErrUserNotInTenant", err)
	}

	// No membership leaked into org 1.
	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserOrg{}).Where("org_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign user was planted into org 1 (count=%d)", count)
	}
}

// AddMember with a same-tenant user id still succeeds.
func TestService_AddMember_SameTenantUserAllowed(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)

	svc := &Service{
		repo:          NewRepository(db),
		idGen:         testIDGen(t),
		userValidator: tenantScopedUserValidator(map[int64]int64{500: 100, 999: 200}),
	}

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	if err := svc.AddMember(ctxA, 1, &AddMemberRequest{UserID: 500}); err != nil {
		t.Fatalf("AddMember same-tenant user: %v", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserOrg{}).Where("org_id = ? AND user_id = ?", 1, 500).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("same-tenant member not written (count=%d)", count)
	}
}

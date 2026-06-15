package group

import (
	"context"
	"errors"
	"testing"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func testIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return g
}

// newGroupReferentDB extends the child-guard DB with the composite unique index
// the AddMember ON CONFLICT(group_id,user_id) upsert relies on (defined in the
// SQL migration, not the gorm model tags — sqlite AutoMigrate omits it).
func newGroupReferentDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newGroupChildGuardDB(t)
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_group_member ON mxid_user_group_member (group_id, user_id)`).Error; err != nil {
		t.Fatalf("create unique index: %v", err)
	}
	return db
}

// tenantScopedUserValidator mimics the production validator: a user id "exists"
// only when its owning tenant matches the caller's tenant context.
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

// AddMember / AddMembers must reject a request-body user id that belongs to a
// different tenant even though the parent group is owned by the caller.
func TestService_AddMember_CrossTenantUserRejected(t *testing.T) {
	db := newGroupReferentDB(t)
	seedGroupWithChildren(t, db) // group 1 -> tenant 100 (static), group 2 -> tenant 200 (dynamic)

	svc := &Service{
		repo:          NewRepository(db),
		idGen:         testIDGen(t),
		userValidator: tenantScopedUserValidator(map[int64]int64{500: 100, 999: 200}),
	}
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Singular AddMember: foreign user 999 (tenant 200) into caller's group 1.
	if err := svc.AddMember(ctxA, 1, &AddMemberRequest{UserID: 999}); !errors.Is(err, ErrUserNotInTenant) {
		t.Fatalf("AddMember foreign user: got %v want ErrUserNotInTenant", err)
	}

	// Batch AddMembers: reject the whole batch if any id is foreign.
	if _, err := svc.AddMembers(ctxA, 1, []int64{500, 999}); !errors.Is(err, ErrUserNotInTenant) {
		t.Fatalf("AddMembers foreign user: got %v want ErrUserNotInTenant", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserGroupMember{}).Where("group_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign user planted into group 1 (count=%d)", count)
	}
}

// Same-tenant users still add successfully (singular + batch).
func TestService_AddMember_SameTenantUserAllowed(t *testing.T) {
	db := newGroupReferentDB(t)
	seedGroupWithChildren(t, db)

	svc := &Service{
		repo:          NewRepository(db),
		idGen:         testIDGen(t),
		userValidator: tenantScopedUserValidator(map[int64]int64{500: 100, 501: 100, 999: 200}),
	}
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	if err := svc.AddMember(ctxA, 1, &AddMemberRequest{UserID: 500}); err != nil {
		t.Fatalf("AddMember same-tenant: %v", err)
	}
	if _, err := svc.AddMembers(ctxA, 1, []int64{501}); err != nil {
		t.Fatalf("AddMembers same-tenant: %v", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserGroupMember{}).Where("group_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("same-tenant members not written (count=%d want 2)", count)
	}
}

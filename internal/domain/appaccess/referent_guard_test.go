package appaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func newPolicyDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&Policy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return g
}

// tenantScopedValidator mimics a tenant-scoped GetByID: an entity id "exists"
// only when its owning tenant matches the caller's tenant context.
func tenantScopedValidator(owners map[int64]int64) EntityValidator {
	return func(ctx context.Context, id int64) (bool, error) {
		owner, ok := owners[id]
		if !ok {
			return false, nil
		}
		s, _ := tenantscope.From(ctx)
		return owner == s.TenantID, nil
	}
}

func newAccessSvc(t *testing.T, db *gorm.DB) *Service {
	s := NewService(NewRepository(db), testIDGen(t), nil)
	s.SetRefValidators(RefValidators{
		App:   tenantScopedValidator(map[int64]int64{1: 100, 2: 200}),
		User:  tenantScopedValidator(map[int64]int64{500: 100, 999: 200}),
		Group: tenantScopedValidator(map[int64]int64{600: 100, 888: 200}),
	})
	return s
}

func appID(v int64) *int64 { return &v }

// AddPolicy must reject a cross-tenant parent app (untrusted path :id).
func TestService_AddPolicy_CrossTenantParentRejected(t *testing.T) {
	db := newPolicyDB(t)
	svc := newAccessSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// app 2 belongs to tenant 200; caller is tenant 100.
	_, err := svc.AddPolicy(ctxA, AddPolicyRequest{
		AppID: appID(2), TenantID: 100, SubjectType: SubjectUser, SubjectID: 500,
	})
	if !errors.Is(err, ErrParentNotInTenant) {
		t.Fatalf("AddPolicy cross-tenant parent: got %v want ErrParentNotInTenant", err)
	}
}

// AddPolicy must reject a cross-tenant subject even when the parent is owned.
func TestService_AddPolicy_CrossTenantSubjectRejected(t *testing.T) {
	db := newPolicyDB(t)
	svc := newAccessSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	_, err := svc.AddPolicy(ctxA, AddPolicyRequest{
		AppID: appID(1), TenantID: 100, SubjectType: SubjectUser, SubjectID: 999,
	})
	if !errors.Is(err, ErrSubjectNotInTenant) {
		t.Fatalf("AddPolicy cross-tenant subject: got %v want ErrSubjectNotInTenant", err)
	}

	var count int64
	if err := db.Model(&Policy{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("policy written despite foreign subject (count=%d)", count)
	}
}

// AddPolicy with same-tenant parent + subject still writes.
func TestService_AddPolicy_SameTenantAllowed(t *testing.T) {
	db := newPolicyDB(t)
	svc := newAccessSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	p, err := svc.AddPolicy(ctxA, AddPolicyRequest{
		AppID: appID(1), TenantID: 100, SubjectType: SubjectUser, SubjectID: 500,
	})
	if err != nil {
		t.Fatalf("AddPolicy same-tenant: %v", err)
	}
	if p == nil {
		t.Fatal("expected policy")
	}

	var count int64
	if err := db.Model(&Policy{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("same-tenant policy not written (count=%d)", count)
	}
}

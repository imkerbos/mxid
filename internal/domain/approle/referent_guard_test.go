package approle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func newApproleDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&AppRole{}, &Binding{}); err != nil {
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

func aid(v int64) *int64 { return &v }

// seedAppRole plants app-role 70 under app 1 (tenant 100) and app-role 71 under
// app 2 (tenant 200).
func seedAppRole(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	rows := []AppRole{
		{ID: 70, AppID: aid(1), TenantID: 100, Code: "admin", Name: "Admin", CreatedAt: time.Now()},
		{ID: 71, AppID: aid(2), TenantID: 200, Code: "admin", Name: "Admin", CreatedAt: time.Now()},
	}
	if err := db.WithContext(sys).Create(&rows).Error; err != nil {
		t.Fatalf("seed app roles: %v", err)
	}
}

func newApproleSvc(t *testing.T, db *gorm.DB) *Service {
	s := NewService(NewRepository(db), testIDGen(t), nil)
	s.SetRefValidators(RefValidators{
		App:  tenantScopedValidator(map[int64]int64{1: 100, 2: 200}),
		User: tenantScopedValidator(map[int64]int64{500: 100, 999: 200}),
	})
	return s
}

// CreateRole must reject a cross-tenant parent app (untrusted path :id).
func TestService_CreateRole_CrossTenantParentRejected(t *testing.T) {
	db := newApproleDB(t)
	svc := newApproleSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	_, err := svc.CreateRole(ctxA, CreateRoleRequest{
		AppID: aid(2), TenantID: 100, Code: "x", Name: "X",
	})
	if !errors.Is(err, ErrParentNotInTenant) {
		t.Fatalf("CreateRole cross-tenant parent: got %v want ErrParentNotInTenant", err)
	}
}

// AddBinding must reject (a) a cross-tenant parent, (b) an app-role that does
// not belong to the parent, and (c) a cross-tenant subject.
func TestService_AddBinding_CrossTenantRejected(t *testing.T) {
	db := newApproleDB(t)
	seedAppRole(t, db)
	svc := newApproleSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// (a) parent app 2 (tenant 200).
	if _, err := svc.AddBinding(ctxA, AddBindingRequest{
		AppID: aid(2), TenantID: 100, AppRoleID: 70, SubjectType: SubjectUser, SubjectID: 500,
	}); !errors.Is(err, ErrParentNotInTenant) {
		t.Fatalf("AddBinding cross-tenant parent: got %v want ErrParentNotInTenant", err)
	}

	// (b) app-role 71 belongs to app 2, not the caller's parent app 1.
	if _, err := svc.AddBinding(ctxA, AddBindingRequest{
		AppID: aid(1), TenantID: 100, AppRoleID: 71, SubjectType: SubjectUser, SubjectID: 500,
	}); !errors.Is(err, ErrAppRoleNotInParent) {
		t.Fatalf("AddBinding foreign app-role: got %v want ErrAppRoleNotInParent", err)
	}

	// (c) foreign subject 999 (tenant 200).
	if _, err := svc.AddBinding(ctxA, AddBindingRequest{
		AppID: aid(1), TenantID: 100, AppRoleID: 70, SubjectType: SubjectUser, SubjectID: 999,
	}); !errors.Is(err, ErrSubjectNotInTenant) {
		t.Fatalf("AddBinding foreign subject: got %v want ErrSubjectNotInTenant", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&Binding{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("binding written despite a foreign referent (count=%d)", count)
	}
}

// AddBinding with same-tenant parent + app-role + subject still writes.
func TestService_AddBinding_SameTenantAllowed(t *testing.T) {
	db := newApproleDB(t)
	seedAppRole(t, db)
	svc := newApproleSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	b, err := svc.AddBinding(ctxA, AddBindingRequest{
		AppID: aid(1), TenantID: 100, AppRoleID: 70, SubjectType: SubjectUser, SubjectID: 500,
	})
	if err != nil {
		t.Fatalf("AddBinding same-tenant: %v", err)
	}
	if b == nil {
		t.Fatal("expected binding")
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&Binding{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("same-tenant binding not written (count=%d)", count)
	}
}

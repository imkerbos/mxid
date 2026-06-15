package group

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newGroupChildGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&UserGroup{}, &UserGroupMember{}, &UserGroupRule{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedGroupWithChildren(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	groups := []UserGroup{
		{ID: 1, TenantID: 100, Name: "a-grp", Code: "a", Type: TypeStatic},
		{ID: 2, TenantID: 200, Name: "b-grp", Code: "b", Type: TypeDynamic},
	}
	if err := db.WithContext(sys).Create(&groups).Error; err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	if err := db.WithContext(sys).Create(&UserGroupMember{ID: 10, GroupID: 2, UserID: 99}).Error; err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if err := db.WithContext(sys).Create(&UserGroupRule{ID: 20, GroupID: 2, Expr: datatypes.JSON([]byte(`{"all":[]}`)), Status: RuleEnabled}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}
}

// Tenant A (100) tampering :id=2 (tenant B's group) must be rejected before any
// tenant-less child (mxid_user_group_member / mxid_user_group_rule) is touched.
func TestService_GroupChildGuard_CrossTenantBlocked(t *testing.T) {
	db := newGroupChildGuardDB(t)
	seedGroupWithChildren(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// mxid_user_group_member read
	if _, _, err := svc.GetMembers(ctxA, 2, 1, 20); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("GetMembers cross-tenant: got %v want ErrGroupNotFound", err)
	}

	// mxid_user_group_member batch write
	if _, err := svc.AddMembers(ctxA, 2, []int64{77}); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("AddMembers cross-tenant: got %v want ErrGroupNotFound", err)
	}
	if _, err := svc.RemoveMembers(ctxA, 2, []int64{99}); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("RemoveMembers cross-tenant: got %v want ErrGroupNotFound", err)
	}

	// mxid_user_group_rule read + sync
	if _, err := svc.GetRule(ctxA, 2); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("GetRule cross-tenant: got %v want ErrGroupNotFound", err)
	}
	if _, err := svc.SyncRule(ctxA, 2); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("SyncRule cross-tenant: got %v want ErrGroupNotFound", err)
	}

	// No writes leaked: tenant B's member row still there, none added.
	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserGroupMember{}).Where("group_id = ?", 2).Count(&count).Error; err != nil {
		t.Fatalf("count members: %v", err)
	}
	if count != 1 {
		t.Fatalf("cross-tenant batch write mutated tenant B members (count=%d)", count)
	}
}

package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

// newChildGuardDB builds an in-memory DB with the tenant-isolation plugin and
// the parent (mxid_user) plus the tenant-less child tables. Mirrors production
// wiring: the column plugin only filters mxid_user; the child tables rely on
// the service-layer parent-ownership guard.
func newChildGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserMFA{}, &MFABackupCode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedUserWithChildren(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	users := []User{
		{ID: 1, TenantID: 100, Username: "alice", Status: StatusActive},
		{ID: 2, TenantID: 200, Username: "bob", Status: StatusActive},
	}
	if err := db.WithContext(sys).Create(&users).Error; err != nil {
		t.Fatalf("seed users: %v", err)
	}
	now := time.Now()
	// bob (tenant 200) owns a detail row and a TOTP factor.
	if err := db.WithContext(sys).Create(&UserDetail{ID: 20, UserID: 2, CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed detail: %v", err)
	}
	if err := db.WithContext(sys).Create(&UserMFA{ID: 30, UserID: 2, Type: MFATypeTotp, Verified: true, CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed mfa: %v", err)
	}
}

// Tenant A (100) must not reach tenant B's (user 2) child rows by tampering
// the :id path param. The guard fetches the parent user under the caller's
// scope first, which 404s, so the child query never runs.
func TestService_ChildGuard_CrossTenantBlocked(t *testing.T) {
	db := newChildGuardDB(t)
	seedUserWithChildren(t, db)
	svc := &Service{repo: NewGormRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// mxid_user_detail
	if _, err := svc.GetDetail(ctxA, 2); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetDetail cross-tenant: got %v want ErrUserNotFound", err)
	}

	// mxid_user_mfa
	if _, err := svc.ListMFA(ctxA, 2); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("ListMFA cross-tenant: got %v want ErrUserNotFound", err)
	}

	// mxid_user_mfa + mxid_user_mfa_backup_code cascade
	if err := svc.DeleteMFA(ctxA, 2, MFATypeTotp); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("DeleteMFA cross-tenant: got %v want ErrUserNotFound", err)
	}

	// The factor must still be there — the guard rejected before any delete.
	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserMFA{}).Where("user_id = ?", 2).Count(&count).Error; err != nil {
		t.Fatalf("count mfa: %v", err)
	}
	if count != 1 {
		t.Fatalf("cross-tenant DeleteMFA wiped tenant B's factor (count=%d)", count)
	}
}

// Same-tenant access still works (the guard is not over-broad).
func TestService_ChildGuard_SameTenantAllowed(t *testing.T) {
	db := newChildGuardDB(t)
	seedUserWithChildren(t, db)
	svc := &Service{repo: NewGormRepository(db)}

	ctxB := tenantscope.WithTenant(context.Background(), 200)

	if _, err := svc.ListMFA(ctxB, 2); err != nil {
		t.Fatalf("ListMFA same-tenant: %v", err)
	}
}

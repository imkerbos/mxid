package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func newAppChildGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&App{}, &AppGroup{}, &AppGroupRel{}, &AppAccess{}, &AppCert{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func tid(v int64) *int64 { return &v }

func seedAppWithChildren(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	now := time.Now()
	apps := []App{
		{ID: 1, TenantID: tid(100), Name: "a-app", Code: "a", Protocol: "oidc", ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
		{ID: 2, TenantID: tid(200), Name: "b-app", Code: "b", Protocol: "oidc", ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
	}
	if err := db.WithContext(sys).Create(&apps).Error; err != nil {
		t.Fatalf("seed apps: %v", err)
	}
	groups := []AppGroup{
		{ID: 11, TenantID: 100, Name: "a-grp", Code: "ag", CreatedAt: now, UpdatedAt: now},
		{ID: 12, TenantID: 200, Name: "b-grp", Code: "bg", CreatedAt: now, UpdatedAt: now},
	}
	if err := db.WithContext(sys).Create(&groups).Error; err != nil {
		t.Fatalf("seed app groups: %v", err)
	}
	// tenant B's child rows (parent app=2 / group=12)
	if err := db.WithContext(sys).Create(&AppAccess{ID: 30, AppID: 2, SubjectType: "user", SubjectID: 9, CreatedAt: now}).Error; err != nil {
		t.Fatalf("seed access: %v", err)
	}
	if err := db.WithContext(sys).Create(&AppCert{ID: 40, AppID: 2, CertType: "signing", Algorithm: "RS256", PublicKey: "pk", PrivateKey: "sk", NotBefore: now, CreatedAt: now}).Error; err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := db.WithContext(sys).Create(&AppGroupRel{ID: 50, AppID: 2, GroupID: 12, CreatedAt: now}).Error; err != nil {
		t.Fatalf("seed rel: %v", err)
	}
}

// Tenant A (100) must not reach tenant B's tenant-less child rows
// (mxid_app_access, mxid_app_cert, mxid_app_group_rel) by tampering the parent
// :id (app/group) or the child :aid/:cid row id.
func TestService_AppChildGuard_CrossTenantBlocked(t *testing.T) {
	db := newAppChildGuardDB(t)
	seedAppWithChildren(t, db)
	svc := &Service{repo: NewGormRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// mxid_app_access list by parent app id
	if _, err := svc.ListAccess(ctxA, 2); !errors.Is(err, ErrAppNotFound) {
		t.Fatalf("ListAccess cross-tenant: got %v want ErrAppNotFound", err)
	}
	// mxid_app_access delete by child row id (:aid) — parent derived from the row
	if err := svc.RemoveAccess(ctxA, 30); !errors.Is(err, ErrAccessNotFound) {
		t.Fatalf("RemoveAccess cross-tenant: got %v want ErrAccessNotFound", err)
	}

	// mxid_app_cert list by parent app id
	if _, err := svc.ListCerts(ctxA, 2); !errors.Is(err, ErrAppNotFound) {
		t.Fatalf("ListCerts cross-tenant: got %v want ErrAppNotFound", err)
	}
	// mxid_app_cert delete by child row id (:cid)
	if err := svc.DeleteCert(ctxA, 40); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("DeleteCert cross-tenant: got %v want ErrCertNotFound", err)
	}

	// mxid_app_group_rel list by parent group id
	if _, err := svc.ListAppsByGroup(ctxA, 12); !errors.Is(err, ErrAppGroupNotFound) {
		t.Fatalf("ListAppsByGroup cross-tenant: got %v want ErrAppGroupNotFound", err)
	}
	// mxid_app_group_rel unlink by parent group + app ids
	if err := svc.RemoveAppFromGroup(ctxA, 12, 2); !errors.Is(err, ErrAppGroupNotFound) {
		t.Fatalf("RemoveAppFromGroup cross-tenant: got %v want ErrAppGroupNotFound", err)
	}

	// Nothing deleted — tenant B's child rows survive.
	sys := tenantscope.SystemContext()
	for _, tc := range []struct {
		name  string
		model interface{}
		id    int64
	}{
		{"access", &AppAccess{}, 30},
		{"cert", &AppCert{}, 40},
		{"rel", &AppGroupRel{}, 50},
	} {
		var n int64
		if err := db.WithContext(sys).Model(tc.model).Where("id = ?", tc.id).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", tc.name, err)
		}
		if n != 1 {
			t.Fatalf("cross-tenant op deleted tenant B %s row (id=%d)", tc.name, tc.id)
		}
	}
}

// Same-tenant access still resolves (guard not over-broad), including the
// child-id delete paths.
func TestService_AppChildGuard_SameTenantAllowed(t *testing.T) {
	db := newAppChildGuardDB(t)
	seedAppWithChildren(t, db)
	svc := &Service{repo: NewGormRepository(db)}

	ctxB := tenantscope.WithTenant(context.Background(), 200)

	if _, err := svc.ListAccess(ctxB, 2); err != nil {
		t.Fatalf("ListAccess same-tenant: %v", err)
	}
	if err := svc.RemoveAccess(ctxB, 30); err != nil {
		t.Fatalf("RemoveAccess same-tenant: %v", err)
	}
	if err := svc.DeleteCert(ctxB, 40); err != nil {
		t.Fatalf("DeleteCert same-tenant: %v", err)
	}
}

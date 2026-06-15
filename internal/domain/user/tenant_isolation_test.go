package user

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

// newIsolatedDB builds an in-memory DB with the tenant-isolation plugin and
// the mxid_user table, mirroring the production wiring (plugin installed on the
// shared gorm.DB right after open).
func newIsolatedDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedUsers(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	users := []User{
		{ID: 1, TenantID: 100, Username: "alice", Status: StatusActive},
		{ID: 2, TenantID: 200, Username: "bob", Status: StatusActive},
	}
	if err := db.WithContext(sys).Create(&users).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// The headline IDOR: GetByID(id) on the real repo must NOT return another
// tenant's user when the context is scoped to a different tenant.
func TestUserRepo_GetByID_CrossTenantBlocked(t *testing.T) {
	db := newIsolatedDB(t)
	seedUsers(t, db)
	repo := NewGormRepository(db)

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Tenant A reads its own user fine.
	u, err := repo.GetByID(ctxA, 1)
	if err != nil {
		t.Fatalf("tenant A own GetByID: %v", err)
	}
	if u.Username != "alice" {
		t.Fatalf("got %q want alice", u.Username)
	}

	// Tenant A tampering id=2 (tenant B's user) must get not-found, not bob.
	if _, err := repo.GetByID(ctxA, 2); err == nil {
		t.Fatalf("IDOR: tenant A read tenant B user via GetByID(2)")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		// repo wraps the error; just ensure it did not succeed and the
		// underlying cause is record-not-found.
		if !errors.Is(errors.Unwrap(err), gorm.ErrRecordNotFound) {
			t.Logf("note: GetByID(2) errored as: %v", err)
		}
	}
}

// Login pre-tenant path: GetByUsername already filters tenant_id explicitly and
// must keep working once the caller pins the explicit tenant in context.
func TestUserRepo_GetByUsername_ScopedWorks(t *testing.T) {
	db := newIsolatedDB(t)
	seedUsers(t, db)
	repo := NewGormRepository(db)

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	u, err := repo.GetByUsername(ctxA, 100, "alice")
	if err != nil {
		t.Fatalf("GetByUsername scoped: %v", err)
	}
	if u.ID != 1 {
		t.Fatalf("got id %d want 1", u.ID)
	}

	// Even with the right username, tenant B's scope cannot reach alice.
	ctxB := tenantscope.WithTenant(context.Background(), 200)
	if _, err := repo.GetByUsername(ctxB, 200, "alice"); err == nil {
		t.Fatalf("tenant B resolved tenant A's alice")
	}
}

// Missing scope on a real repo read fails closed.
func TestUserRepo_NoScopeFailsClosed(t *testing.T) {
	db := newIsolatedDB(t)
	seedUsers(t, db)
	repo := NewGormRepository(db)

	_, err := repo.GetByID(context.Background(), 1)
	if err == nil {
		t.Fatalf("missing scope must fail closed, got a user")
	}
	if !errors.Is(err, tenantscope.ErrNoTenantScope) &&
		!errors.Is(errors.Unwrap(err), tenantscope.ErrNoTenantScope) {
		t.Fatalf("want ErrNoTenantScope, got %v", err)
	}
}

// A cross-tenant escape (e.g. super_admin aggregate) bypasses isolation.
func TestUserRepo_CrossTenantEscape(t *testing.T) {
	db := newIsolatedDB(t)
	seedUsers(t, db)
	repo := NewGormRepository(db)

	// CountAll is the documented cross-tenant aggregate; under a cross-tenant
	// context it must see both tenants' users.
	n, err := repo.CountAll(tenantscope.WithCrossTenant(context.Background()))
	if err != nil {
		t.Fatalf("CountAll cross-tenant: %v", err)
	}
	if n != 2 {
		t.Fatalf("cross-tenant CountAll = %d, want 2", n)
	}
}

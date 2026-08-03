package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&Tenant{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return &Service{repo: NewRepository(db), idGen: idGen}
}

// seedTenant inserts a row directly through the repository — tenants are
// seeded by migration in production (no create API; single-tenant product).
func seedTenant(t *testing.T, svc *Service, name, code string) *Tenant {
	t.Helper()
	row := &Tenant{
		ID:     svc.idGen.Generate(),
		Name:   name,
		Code:   code,
		Status: StatusEnabled,
		Config: datatypes.JSON([]byte("{}")),
	}
	if err := svc.repo.Create(context.Background(), row); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return row
}

func TestService_Get(t *testing.T) {
	svc := newTestService(t)
	seeded := seedTenant(t, svc, "Acme", "acme")

	got, err := svc.Get(context.Background(), seeded.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Code != "acme" || got.Name != "Acme" {
		t.Errorf("got %+v, want code=acme name=Acme", got)
	}
}

func TestService_GetByCode(t *testing.T) {
	svc := newTestService(t)
	seeded := seedTenant(t, svc, "Acme", "acme")

	got, err := svc.GetByCode(context.Background(), "acme")
	if err != nil {
		t.Fatalf("get by code: %v", err)
	}
	if got.ID != seeded.ID {
		t.Errorf("got id %d, want %d", got.ID, seeded.ID)
	}
}

func TestService_GetNotFound(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Get(context.Background(), 999999); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("get missing: got %v, want ErrTenantNotFound", err)
	}
}

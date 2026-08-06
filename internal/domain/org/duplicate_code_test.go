package org

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// withOrgCodeUniqueIndex adds the (tenant_id, code) unique constraint that
// migration 000003 puts on mxid_organization. AutoMigrate does not create it —
// the model carries no uniqueIndex tag, the constraint lives only in the
// migration SQL — so without this the duplicate simply inserts and the test
// would pass against the broken code.
func withOrgCodeUniqueIndex(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`CREATE UNIQUE INDEX mxid_organization_tenant_id_code_key
		ON mxid_organization(tenant_id, code)`).Error; err != nil {
		t.Fatalf("create unique index: %v", err)
	}
}

// Reusing a department code is the administrator's mistake, and saying so is
// the difference between "pick another code" and a 500 that reads as "the
// server is broken, try again" — which is exactly the retry loop the same
// defect produced for user groups.
func TestService_Create_DuplicateCodeIsAConflict(t *testing.T) {
	db := newOrgChildGuardDB(t)
	withOrgCodeUniqueIndex(t, db)

	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	svc := &Service{repo: NewRepository(db), idGen: idGen}
	ctx := tenantscope.WithTenant(context.Background(), 100)

	if _, err := svc.Create(ctx, 100, &CreateOrgRequest{Name: "Ops", Code: "ops"}); err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = svc.Create(ctx, 100, &CreateOrgRequest{Name: "Ops again", Code: "ops"})
	if err == nil {
		t.Fatal("second create with the same code succeeded — the constraint is not being exercised")
	}
	if !errors.Is(err, ErrOrgCodeExists) {
		t.Fatalf("want ErrOrgCodeExists, got %v", err)
	}
}

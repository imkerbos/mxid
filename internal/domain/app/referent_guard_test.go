package app

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

// AddAccess (parent app already guarded) must reject a request-body subject id
// that belongs to a different tenant.
func TestService_AddAccess_CrossTenantSubjectRejected(t *testing.T) {
	db := newAppChildGuardDB(t)
	seedAppWithChildren(t, db) // app 1 -> tenant 100, app 2 -> tenant 200

	svc := &Service{
		repo:  NewGormRepository(db),
		idGen: testIDGen(t),
		subjectValidators: AccessSubjectValidators{
			User: tenantScopedValidator(map[int64]int64{500: 100, 999: 200}),
		},
	}
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Caller (tenant 100) owns app 1. Authorizing foreign user 999 (tenant 200)
	// must be rejected.
	if _, err := svc.AddAccess(ctxA, 1, &AddAccessRequest{SubjectType: AccessSubjectUser, SubjectID: 999}); !errors.Is(err, ErrSubjectNotInTenant) {
		t.Fatalf("AddAccess foreign subject: got %v want ErrSubjectNotInTenant", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&AppAccess{}).Where("app_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign subject authorized onto app 1 (count=%d)", count)
	}
}

// AddAccess with a same-tenant subject still succeeds.
func TestService_AddAccess_SameTenantSubjectAllowed(t *testing.T) {
	db := newAppChildGuardDB(t)
	seedAppWithChildren(t, db)

	svc := &Service{
		repo:  NewGormRepository(db),
		idGen: testIDGen(t),
		subjectValidators: AccessSubjectValidators{
			User: tenantScopedValidator(map[int64]int64{500: 100, 999: 200}),
		},
	}
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	if _, err := svc.AddAccess(ctxA, 1, &AddAccessRequest{SubjectType: AccessSubjectUser, SubjectID: 500}); err != nil {
		t.Fatalf("AddAccess same-tenant subject: %v", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&AppAccess{}).Where("app_id = ? AND subject_id = ?", 1, 500).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("same-tenant access not written (count=%d)", count)
	}
}

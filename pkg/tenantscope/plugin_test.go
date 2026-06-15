package tenantscope_test

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

// scopedModel is a tenant-scoped table (implements tenantscope.Tenanted).
type scopedModel struct {
	ID       int64 `gorm:"primaryKey"`
	TenantID int64 `gorm:"column:tenant_id"`
	Name     string
}

func (scopedModel) TableName() string  { return "scoped_model" }
func (scopedModel) TenantScoped()       {}

// globalModel is NOT tenant-scoped (no marker) — must never be filtered.
type globalModel struct {
	ID   int64 `gorm:"primaryKey"`
	Name string
}

func (globalModel) TableName() string { return "global_model" }

// sharedModel mirrors mxid_app: nullable tenant_id where NULL = shared.
type sharedModel struct {
	ID       int64  `gorm:"primaryKey"`
	TenantID *int64 `gorm:"column:tenant_id"`
	Name     string
}

func (sharedModel) TableName() string { return "shared_model" }
func (sharedModel) TenantScoped()     {}
func (sharedModel) TenantScopePredicate() (string, bool) {
	return "tenant_id = ? OR tenant_id IS NULL", true
}

// settingModel mirrors mxid_setting: tenant_id=0 = global default.
type settingModel struct {
	ID       int64 `gorm:"primaryKey"`
	TenantID int64 `gorm:"column:tenant_id"`
	Name     string
}

func (settingModel) TableName() string { return "setting_model" }
func (settingModel) TenantScoped()     {}
func (settingModel) TenantScopePredicate() (string, bool) {
	return "tenant_id IN (?, 0)", true
}

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("install plugin: %v", err)
	}
	if err := db.AutoMigrate(&scopedModel{}, &globalModel{}, &sharedModel{}, &settingModel{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// seedScoped inserts rows for tenant A and B using a system context so the
// plugin does not interfere with test fixtures.
func seedScoped(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	rows := []scopedModel{
		{ID: 1, TenantID: 100, Name: "a-row"},
		{ID: 2, TenantID: 200, Name: "b-row"},
	}
	if err := db.WithContext(sys).Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// (a) tenant A scope cannot read a tenant B row.
func TestTenantIsolation_CrossTenantReadBlocked(t *testing.T) {
	db := newTestDB(t)
	seedScoped(t, db)

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Tenant A can read its own row.
	var ownRow scopedModel
	if err := db.WithContext(ctxA).First(&ownRow, 1).Error; err != nil {
		t.Fatalf("tenant A reading own row: %v", err)
	}
	if ownRow.Name != "a-row" {
		t.Fatalf("got %q, want a-row", ownRow.Name)
	}

	// Tenant A attempts to read tenant B's row by primary key (the IDOR).
	var stolen scopedModel
	err := db.WithContext(ctxA).First(&stolen, 2).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("cross-tenant read of id=2 by tenant A: got err=%v, want ErrRecordNotFound", err)
	}

	// A list query for tenant A must only see tenant A rows.
	var list []scopedModel
	if err := db.WithContext(ctxA).Find(&list).Error; err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].TenantID != 100 {
		t.Fatalf("tenant A list leaked rows: %+v", list)
	}
}

// (a') cross-tenant UPDATE / DELETE are also blocked.
func TestTenantIsolation_CrossTenantWriteBlocked(t *testing.T) {
	db := newTestDB(t)
	seedScoped(t, db)

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Update scoped to tenant A — must not touch tenant B's id=2.
	res := db.WithContext(ctxA).Model(&scopedModel{}).
		Where("id = ?", 2).Update("name", "hacked")
	if res.Error != nil {
		t.Fatalf("update: %v", res.Error)
	}
	if res.RowsAffected != 0 {
		t.Fatalf("tenant A updated tenant B row (%d rows)", res.RowsAffected)
	}

	// Delete by id=2 from tenant A — must affect nothing.
	res = db.WithContext(ctxA).Where("id = ?", 2).Delete(&scopedModel{})
	if res.Error != nil {
		t.Fatalf("delete: %v", res.Error)
	}
	if res.RowsAffected != 0 {
		t.Fatalf("tenant A deleted tenant B row (%d rows)", res.RowsAffected)
	}

	// Tenant B's row still intact.
	var b scopedModel
	if err := db.WithContext(tenantscope.SystemContext()).First(&b, 2).Error; err != nil {
		t.Fatalf("tenant B row gone: %v", err)
	}
	if b.Name != "b-row" {
		t.Fatalf("tenant B row mutated: %q", b.Name)
	}
}

// (b) SystemContext / CrossTenant bypass the filter.
func TestTenantIsolation_EscapesBypass(t *testing.T) {
	db := newTestDB(t)
	seedScoped(t, db)

	// System sees everything.
	var all []scopedModel
	if err := db.WithContext(tenantscope.SystemContext()).Find(&all).Error; err != nil {
		t.Fatalf("system find: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("system context expected 2 rows, got %d", len(all))
	}

	// CrossTenant sees everything too.
	cross := tenantscope.WithCrossTenant(tenantscope.WithTenant(context.Background(), 100))
	var allCross []scopedModel
	if err := db.WithContext(cross).Find(&allCross).Error; err != nil {
		t.Fatalf("cross-tenant find: %v", err)
	}
	if len(allCross) != 2 {
		t.Fatalf("cross-tenant expected 2 rows, got %d", len(allCross))
	}
}

// (c) Missing scope on a tenant-scoped model fails closed.
func TestTenantIsolation_MissingScopeFailsClosed(t *testing.T) {
	db := newTestDB(t)
	seedScoped(t, db)

	// No scope in context.
	var row scopedModel
	err := db.WithContext(context.Background()).First(&row, 1).Error
	if !errors.Is(err, tenantscope.ErrNoTenantScope) {
		t.Fatalf("missing scope: got err=%v, want ErrNoTenantScope", err)
	}

	// A list without scope must error too (never return all rows).
	var list []scopedModel
	err = db.WithContext(context.Background()).Find(&list).Error
	if !errors.Is(err, tenantscope.ErrNoTenantScope) {
		t.Fatalf("missing scope list: got err=%v (rows=%d), want ErrNoTenantScope", err, len(list))
	}
	if len(list) != 0 {
		t.Fatalf("fail-closed leaked %d rows", len(list))
	}

	// A zero/invalid tenant id is treated as no scope (fail closed).
	err = db.WithContext(tenantscope.WithTenant(context.Background(), 0)).First(&row, 1).Error
	if !errors.Is(err, tenantscope.ErrNoTenantScope) {
		t.Fatalf("zero tenant: got err=%v, want ErrNoTenantScope", err)
	}
}

// (d) A global model (no marker) is unaffected even without any scope.
func TestTenantIsolation_GlobalModelUnaffected(t *testing.T) {
	db := newTestDB(t)
	sys := tenantscope.SystemContext()
	if err := db.WithContext(sys).Create(&[]globalModel{{ID: 1, Name: "x"}, {ID: 2, Name: "y"}}).Error; err != nil {
		t.Fatalf("seed global: %v", err)
	}

	// No scope at all — global model must still read fine.
	var rows []globalModel
	if err := db.WithContext(context.Background()).Find(&rows).Error; err != nil {
		t.Fatalf("global find without scope: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("global model filtered: got %d rows", len(rows))
	}

	// And a scoped-to-tenant context must not filter it either.
	var one globalModel
	if err := db.WithContext(tenantscope.WithTenant(context.Background(), 999)).First(&one, 2).Error; err != nil {
		t.Fatalf("global read under tenant scope: %v", err)
	}
}

// Special predicate: shared (nullable tenant) rows surface in every tenant.
func TestTenantIsolation_SharedNullablePredicate(t *testing.T) {
	db := newTestDB(t)
	sys := tenantscope.SystemContext()
	tA := int64(100)
	tB := int64(200)
	rows := []sharedModel{
		{ID: 1, TenantID: &tA, Name: "tenant-a-app"},
		{ID: 2, TenantID: &tB, Name: "tenant-b-app"},
		{ID: 3, TenantID: nil, Name: "shared-app"},
	}
	if err := db.WithContext(sys).Create(&rows).Error; err != nil {
		t.Fatalf("seed shared: %v", err)
	}

	ctxA := tenantscope.WithTenant(context.Background(), tA)
	var list []sharedModel
	if err := db.WithContext(ctxA).Order("id").Find(&list).Error; err != nil {
		t.Fatalf("shared find: %v", err)
	}
	// Tenant A sees its own row + the shared row, but NOT tenant B's row.
	if len(list) != 2 {
		t.Fatalf("shared predicate: tenant A got %d rows, want 2: %+v", len(list), list)
	}
	for _, r := range list {
		if r.Name == "tenant-b-app" {
			t.Fatalf("tenant A leaked tenant B app")
		}
	}
}

// Special predicate: setting tenant_id=0 global default visible to all tenants.
func TestTenantIsolation_SettingGlobalDefaultPredicate(t *testing.T) {
	db := newTestDB(t)
	sys := tenantscope.SystemContext()
	rows := []settingModel{
		{ID: 1, TenantID: 0, Name: "global-default"},
		{ID: 2, TenantID: 100, Name: "tenant-a-override"},
		{ID: 3, TenantID: 200, Name: "tenant-b-override"},
	}
	if err := db.WithContext(sys).Create(&rows).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	var list []settingModel
	if err := db.WithContext(ctxA).Order("id").Find(&list).Error; err != nil {
		t.Fatalf("setting find: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("setting predicate: tenant A got %d rows, want 2 (global + own): %+v", len(list), list)
	}
	for _, r := range list {
		if r.TenantID == 200 {
			t.Fatalf("tenant A leaked tenant B setting")
		}
	}
}

// Create on a nullable-tenant model (mxid_app style) must NOT stamp a tenant
// over an intentional NULL (shared app), and must preserve an explicit tenant.
func TestTenantIsolation_CreateNullableTenantPreserved(t *testing.T) {
	db := newTestDB(t)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Shared row: tenant_id intentionally nil — must stay nil.
	shared := sharedModel{ID: 20, TenantID: nil, Name: "shared"}
	if err := db.WithContext(ctxA).Create(&shared).Error; err != nil {
		t.Fatalf("create shared: %v", err)
	}
	var got sharedModel
	if err := db.WithContext(tenantscope.SystemContext()).First(&got, 20).Error; err != nil {
		t.Fatalf("readback: %v", err)
	}
	if got.TenantID != nil {
		t.Fatalf("stamp overwrote intentional NULL tenant: %v", *got.TenantID)
	}

	// Explicit tenant on a nullable model must be preserved as-is.
	tB := int64(200)
	explicit := sharedModel{ID: 21, TenantID: &tB, Name: "explicit"}
	if err := db.WithContext(ctxA).Create(&explicit).Error; err != nil {
		t.Fatalf("create explicit: %v", err)
	}
	var got2 sharedModel
	if err := db.WithContext(tenantscope.SystemContext()).First(&got2, 21).Error; err != nil {
		t.Fatalf("readback explicit: %v", err)
	}
	if got2.TenantID == nil || *got2.TenantID != 200 {
		t.Fatalf("explicit nullable tenant not preserved: %v", got2.TenantID)
	}
}

// Create stamps tenant_id when the caller left it zero.
func TestTenantIsolation_CreateStampsTenant(t *testing.T) {
	db := newTestDB(t)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	row := scopedModel{ID: 10, Name: "no-tenant-set"}
	if err := db.WithContext(ctxA).Create(&row).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	if row.TenantID != 100 {
		t.Fatalf("create did not stamp tenant_id: got %d", row.TenantID)
	}

	// Read back under tenant A — proves the stamp landed in the right tenant.
	var got scopedModel
	if err := db.WithContext(ctxA).First(&got, 10).Error; err != nil {
		t.Fatalf("readback: %v", err)
	}
	if got.TenantID != 100 {
		t.Fatalf("stamped tenant mismatch: %d", got.TenantID)
	}
}

// childModel mirrors the documented residual: a child table that derives
// tenancy from a parent FK and has NO tenant_id column of its own. The plugin
// CANNOT filter a column that does not exist, so this table is intentionally
// EXEMPT. This test PROVES the residual cross-tenant exposure is real so the
// follow-up (service-layer parent-ownership guard) is not forgotten.
type childModel struct {
	ID     int64 `gorm:"primaryKey"`
	UserID int64 `gorm:"column:user_id"`
	Secret string
}

func (childModel) TableName() string { return "child_model" }
func (childModel) TenantScoped()     {} // marker present, but no tenant_id col

func TestPlugin_ChildTableResidualIsReachableCrossTenant(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&childModel{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sys := tenantscope.SystemContext()
	// user 1 belongs to tenant 100, user 2 to tenant 200 (parent linkage only).
	if err := db.WithContext(sys).Create(&[]childModel{
		{ID: 1, UserID: 1, Secret: "tenantA-secret"},
		{ID: 2, UserID: 2, Secret: "tenantB-secret"},
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Tenant A scoped context tampering child id=2 (tenant B's child row).
	// Because child_model has no tenant_id column, the plugin no-ops and the
	// row IS returned. This documents the residual: the column filter cannot
	// protect FK-derived children; a parent-ownership guard is required.
	ctxA := tenantscope.WithTenant(context.Background(), 100)
	var got childModel
	err := db.WithContext(ctxA).First(&got, 2).Error
	if err != nil {
		t.Fatalf("expected child row to be reachable (documenting residual), got err: %v", err)
	}
	if got.Secret != "tenantB-secret" {
		t.Fatalf("unexpected row: %+v", got)
	}
	t.Logf("RESIDUAL CONFIRMED: tenant 100 ctx read child_model id=2 (tenant B child) -> %q. Needs parent-ownership guard at service layer.", got.Secret)
}

// A Joins from a non-marked scan target onto a tenant-scoped table must not
// crash or be filtered by the plugin (the plugin keys off the scan struct's
// schema, which here has no marker). Confirms the authz EffectiveBindings hot
// path style query is auto-exempt and produces no ambiguous-column SQL.
func TestPlugin_JoinScanStructAutoExempt(t *testing.T) {
	db := newTestDB(t)
	sys := tenantscope.SystemContext()
	if err := db.WithContext(sys).Create(&[]scopedModel{
		{ID: 1, TenantID: 100, Name: "a"},
		{ID: 2, TenantID: 200, Name: "b"},
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Anonymous scan target, no marker -> plugin no-ops even with a tenant ctx.
	ctxA := tenantscope.WithTenant(context.Background(), 100)
	type nameRow struct{ Name string }
	var rows []nameRow
	err := db.WithContext(ctxA).Table("scoped_model").
		Select("name").Where("tenant_id = ?", 200).Scan(&rows).Error
	if err != nil {
		t.Fatalf("table scan with explicit where: %v", err)
	}
	// Explicit WHERE tenant_id=200 honored, plugin did NOT also inject =100
	// (which would have produced zero rows / contradiction).
	if len(rows) != 1 || rows[0].Name != "b" {
		t.Fatalf("Table()/scan-struct query was unexpectedly filtered by plugin: %+v", rows)
	}
}

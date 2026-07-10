package app

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/app"
)

// TestListAuthorizedAppGroups_ExcludesDeletedAndDisabled proves the sidebar
// group count only tallies apps that actually surface in the card list —
// i.e. apps that exist AND are enabled. Two regressions are covered:
//
//   - orphan rel: an app was hard-deleted but its mxid_app_group_rel row did
//     NOT cascade away (observed in prod where the FK cascade never fired),
//     leaving a rel pointing at a non-existent app.
//   - disabled app: the app row exists with status != Enabled; the card list
//     filters it out (adapters_portal.go:267) but the count query historically
//     did not.
//
// Before the fix the count query scanned mxid_app_group_rel directly and
// returned 4; the list only ever rendered the 2 live+enabled apps.
func TestListAuthorizedAppGroups_ExcludesDeletedAndDisabled(t *testing.T) {
	db := newGroupCountTestDB(t)
	sys := context.Background()
	now := time.Now()
	tenantID := int64(100)

	// One group, tenant-scoped.
	if err := db.WithContext(sys).Create(&app.AppGroup{
		ID: 10, TenantID: tenantID, Name: "devops", Code: "devops",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}

	tid := func(v int64) *int64 { return &v }
	apps := []app.App{
		{ID: 1, TenantID: tid(tenantID), Name: "jenkins-prod", Code: "jp", Protocol: "oidc", Scope: app.ScopeTenant, Status: app.StatusEnabled, ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
		{ID: 2, TenantID: tid(tenantID), Name: "jenkins-uat", Code: "ju", Protocol: "oidc", Scope: app.ScopeTenant, Status: app.StatusEnabled, ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
		{ID: 3, TenantID: tid(tenantID), Name: "jenkins-old", Code: "jo", Protocol: "oidc", Scope: app.ScopeTenant, Status: app.StatusDisabled, ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
	}
	if err := db.WithContext(sys).Create(&apps).Error; err != nil {
		t.Fatalf("seed apps: %v", err)
	}

	// Rels: 2 live+enabled, 1 disabled (app 3), 1 orphan (app 99 never existed).
	rels := []app.AppGroupRel{
		{ID: 1, AppID: 1, GroupID: 10, CreatedAt: now},
		{ID: 2, AppID: 2, GroupID: 10, CreatedAt: now},
		{ID: 3, AppID: 3, GroupID: 10, CreatedAt: now},
		{ID: 4, AppID: 99, GroupID: 10, CreatedAt: now},
	}
	if err := db.WithContext(sys).Create(&rels).Error; err != nil {
		t.Fatalf("seed rels: %v", err)
	}

	adapter := &portalAppQuerierAdapter{
		app:       &bootstrap.App{DB: db},
		appModule: &app.Module{Repo: app.NewGormRepository(db)},
		accessSvc: nil, // no access gating → count is driven purely by live+enabled filter
	}

	groups, err := adapter.ListAuthorizedAppGroups(sys, 1, tenantID)
	if err != nil {
		t.Fatalf("ListAuthorizedAppGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if got := groups[0].AppCount; got != 2 {
		t.Fatalf("devops AppCount = %d, want 2 (deleted+disabled must be excluded)", got)
	}
}

func newGroupCountTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&app.App{}, &app.AppGroup{}, &app.AppGroupRel{}, &app.AppAccess{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

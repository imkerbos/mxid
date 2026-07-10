package app

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/app"
)

// TestListAuthorizedApps_PopulatesEnv proves the per-app environment label
// flows from the mxid_app.env column through ListAuthorizedApps into the
// portal AppInfo.Env the frontend groups by. A NULL env surfaces as "".
func TestListAuthorizedApps_PopulatesEnv(t *testing.T) {
	db := newGroupCountTestDB(t)
	sys := context.Background()
	now := time.Now()
	tenantID := int64(100)
	tid := func(v int64) *int64 { return &v }
	envp := func(s string) *string { return &s }

	apps := []app.App{
		{ID: 1, TenantID: tid(tenantID), Name: "jenkins-prod", Code: "jp", Protocol: "oidc", Scope: app.ScopeTenant, Status: app.StatusEnabled, Env: envp("prod"), ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
		{ID: 2, TenantID: tid(tenantID), Name: "jenkins-uat", Code: "ju", Protocol: "oidc", Scope: app.ScopeTenant, Status: app.StatusEnabled, Env: envp("uat"), ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
		{ID: 3, TenantID: tid(tenantID), Name: "unlabelled", Code: "un", Protocol: "oidc", Scope: app.ScopeTenant, Status: app.StatusEnabled, Env: nil, ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"), CreatedAt: now, UpdatedAt: now},
	}
	if err := db.WithContext(sys).Create(&apps).Error; err != nil {
		t.Fatalf("seed apps: %v", err)
	}

	adapter := &portalAppQuerierAdapter{
		app:       &bootstrap.App{DB: db},
		appModule: &app.Module{Repo: app.NewGormRepository(db)},
		accessSvc: nil,
	}

	list, err := adapter.ListAuthorizedApps(sys, 1, tenantID, "")
	if err != nil {
		t.Fatalf("ListAuthorizedApps: %v", err)
	}
	byID := map[int64]string{}
	for _, a := range list {
		byID[a.ID] = a.Env
	}
	if byID[1] != "prod" {
		t.Fatalf("app 1 Env = %q, want prod", byID[1])
	}
	if byID[2] != "uat" {
		t.Fatalf("app 2 Env = %q, want uat", byID[2])
	}
	if byID[3] != "" {
		t.Fatalf("app 3 Env = %q, want empty (unlabelled)", byID[3])
	}
}

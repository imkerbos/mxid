package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/gateway/portal"
)

// launchAccessDB adds the access-policy table to the portal adapter test DB.
func launchAccessDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newGroupCountTestDB(t)
	if err := db.AutoMigrate(&appaccess.Policy{}); err != nil {
		t.Fatalf("migrate policy: %v", err)
	}
	return db
}

// seedLaunchApp stores one OIDC app whose home URL is the launch target, plus
// an allow rule for exactly one user.
func seedLaunchApp(t *testing.T, db *gorm.DB, tenantID, allowedUserID int64) int64 {
	t.Helper()
	now := time.Now()
	tid := tenantID
	appID := int64(4242)
	home := "https://payroll.example/"
	clientID := "payroll-client"
	row := app.App{
		ID: appID, TenantID: &tid, Name: "payroll", Code: "payroll",
		Protocol: app.ProtocolOIDC, Scope: app.ScopeTenant, Status: app.StatusEnabled,
		HomeURL: &home, ClientID: &clientID,
		ProtocolConfig: []byte("{}"), RedirectURIs: []byte("[]"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed app: %v", err)
	}
	policy := appaccess.Policy{
		ID: 1, AppID: &appID, TenantID: tenantID,
		SubjectType: appaccess.SubjectUser, SubjectID: allowedUserID,
		Effect: appaccess.EffectAllow, CreatedAt: now,
	}
	if err := db.Create(&policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return appID
}

func newLaunchAdapter(db *gorm.DB) *portalAppQuerierAdapter {
	return &portalAppQuerierAdapter{
		app:       &bootstrap.App{DB: db},
		appModule: &app.Module{Repo: app.NewGormRepository(db)},
		issuer:    "https://idp.example",
		accessSvc: appaccess.NewService(appaccess.NewRepository(db), nil, nil),
	}
}

// GetAppLaunchURL took a userID and ignored it: any signed-in portal user could
// walk app ids and read an unauthorized app's launch target (OIDC client_id,
// CAS service URL, a form app's third-party login page) and stamp an
// app.launched audit row under their own name.
func TestGetAppLaunchURL_UnauthorizedUserDenied(t *testing.T) {
	db := launchAccessDB(t)
	tenantID := int64(100)
	appID := seedLaunchApp(t, db, tenantID, 7)

	adapter := newLaunchAdapter(db)
	url, err := adapter.GetAppLaunchURL(context.Background(), appID, 9, tenantID)
	if !errors.Is(err, portal.ErrAppAccessDenied) {
		t.Fatalf("unauthorized launch: want ErrAppAccessDenied, got url=%q err=%v", url, err)
	}
}

// The legitimate path must keep working: the user the policy allows launches.
func TestGetAppLaunchURL_AuthorizedUserAllowed(t *testing.T) {
	db := launchAccessDB(t)
	tenantID := int64(100)
	appID := seedLaunchApp(t, db, tenantID, 7)

	adapter := newLaunchAdapter(db)
	url, err := adapter.GetAppLaunchURL(context.Background(), appID, 7, tenantID)
	if err != nil {
		t.Fatalf("authorized launch: %v", err)
	}
	if url != "https://payroll.example/" {
		t.Fatalf("authorized launch url = %q, want the app home URL", url)
	}
}

// Fail closed: no access-policy service wired means no decision, not an allow.
func TestGetAppLaunchURL_NoAccessServiceDenies(t *testing.T) {
	db := launchAccessDB(t)
	tenantID := int64(100)
	appID := seedLaunchApp(t, db, tenantID, 7)

	adapter := newLaunchAdapter(db)
	adapter.accessSvc = nil
	if _, err := adapter.GetAppLaunchURL(context.Background(), appID, 7, tenantID); !errors.Is(err, portal.ErrAppAccessDenied) {
		t.Fatalf("nil access service: want ErrAppAccessDenied, got %v", err)
	}
}

// stubAccessRepo answers AppsForUser from a fixed set. The real repository's
// query is PostgreSQL-only (ltree containment on the org subtree), so the list
// adapters are exercised through the Repository seam instead.
type stubAccessRepo struct{ allowed []int64 }

func (s stubAccessRepo) ListByApp(context.Context, int64, int64) ([]*appaccess.Policy, error) {
	return nil, nil
}
func (s stubAccessRepo) ListOwnByApp(context.Context, int64, int64) ([]*appaccess.Policy, error) {
	return nil, nil
}
func (s stubAccessRepo) ListByAppGroup(context.Context, int64, int64) ([]*appaccess.Policy, error) {
	return nil, nil
}
func (s stubAccessRepo) Create(context.Context, *appaccess.Policy) error { return nil }
func (s stubAccessRepo) GetByID(context.Context, int64, int64) (*appaccess.Policy, error) {
	return nil, nil
}
func (s stubAccessRepo) Delete(context.Context, int64) error { return nil }
func (s stubAccessRepo) DeleteBySubject(context.Context, string, int64) (int64, error) {
	return 0, nil
}
func (s stubAccessRepo) AppsForUser(context.Context, int64, int64) ([]int64, error) {
	return s.allowed, nil
}

func stubAccessSvc(allowed ...int64) *appaccess.Service {
	return appaccess.NewService(stubAccessRepo{allowed: allowed}, nil, nil)
}

// Fail closed, matching GetAppLaunchURL: an absent access-policy service is a
// missing decision, not an allow. Before this the card list returned EVERY
// enabled app.
func TestListAuthorizedApps_NoAccessServiceDenies(t *testing.T) {
	db := launchAccessDB(t)
	tenantID := int64(100)
	seedLaunchApp(t, db, tenantID, 7)

	adapter := newLaunchAdapter(db)
	adapter.accessSvc = nil
	list, err := adapter.ListAuthorizedApps(context.Background(), 7, tenantID, "")
	if err == nil {
		t.Fatalf("nil access service: want an error, got %d apps", len(list))
	}
	if len(list) != 0 {
		t.Fatalf("nil access service leaked %d apps", len(list))
	}
}

func TestListAuthorizedAppGroups_NoAccessServiceDenies(t *testing.T) {
	db := launchAccessDB(t)
	tenantID := int64(100)
	seedLaunchApp(t, db, tenantID, 7)

	if err := db.Create(&app.AppGroup{
		ID: 10, TenantID: tenantID, Name: "devops", Code: "devops",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}

	adapter := newLaunchAdapter(db)
	adapter.accessSvc = nil
	groups, err := adapter.ListAuthorizedAppGroups(context.Background(), 7, tenantID)
	if err == nil {
		t.Fatalf("nil access service: want an error, got %d groups", len(groups))
	}
	if len(groups) != 0 {
		t.Fatalf("nil access service leaked %d groups", len(groups))
	}
}

// The wired path must be unchanged: allowed app in, everything else out.
func TestListAuthorizedApps_WiredServiceFiltersUnchanged(t *testing.T) {
	db := launchAccessDB(t)
	tenantID := int64(100)
	appID := seedLaunchApp(t, db, tenantID, 7)

	adapter := newLaunchAdapter(db)
	adapter.accessSvc = stubAccessSvc(appID)
	list, err := adapter.ListAuthorizedApps(context.Background(), 7, tenantID, "")
	if err != nil {
		t.Fatalf("wired access service: %v", err)
	}
	if len(list) != 1 || list[0].ID != appID {
		t.Fatalf("allowed app missing from list: %+v", list)
	}

	adapter.accessSvc = stubAccessSvc() // nothing allowed
	list, err = adapter.ListAuthorizedApps(context.Background(), 9, tenantID, "")
	if err != nil {
		t.Fatalf("wired access service (deny): %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("unauthorized user saw %d apps", len(list))
	}
}

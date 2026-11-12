package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/domain/consent"
)

// launchFake scripts GetAppLaunchURL so only the handler's error mapping is
// under test (real policy enforcement is covered in the adapter's own test).
type launchFake struct {
	url string
	err error
}

func (f launchFake) ListAuthorizedApps(context.Context, int64, int64, string) ([]*AppInfo, error) {
	return nil, nil
}
func (f launchFake) GetAppLaunchURL(context.Context, int64, int64, int64) (string, error) {
	return f.url, f.err
}
func (f launchFake) AppName(context.Context, int64) (string, error) { return "payroll", nil }
func (f launchFake) ListAuthorizedAppGroups(context.Context, int64, int64) ([]*AppGroupInfo, error) {
	return nil, nil
}
func (f launchFake) ListFavoriteAppIDs(context.Context, int64) ([]int64, error) { return nil, nil }
func (f launchFake) AddFavorite(context.Context, int64, int64, int64) error     { return nil }
func (f launchFake) RemoveFavorite(context.Context, int64, int64) error         { return nil }
func (f launchFake) ReorderFavorites(context.Context, int64, []int64) error     { return nil }
func (f launchFake) ListRecentAppIDs(context.Context, int64, int64, int) ([]int64, error) {
	return nil, nil
}

func launchStatus(t *testing.T, q launchFake) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &appsHandler{appQuerier: q}
	r := gin.New()
	r.Use(withUser(9))
	r.GET("/apps/:id/launch", h.launchApp)

	req := httptest.NewRequest(http.MethodGet, "/apps/4242/launch", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// A refused launch is a 403 — not a 500, and not an app.launched audit row
// (the handler returns before publishing, so nothing lands under the caller).
func TestLaunchApp_AccessDeniedReturns403(t *testing.T) {
	w := launchStatus(t, launchFake{err: ErrAppAccessDenied})
	if w.Code != http.StatusForbidden {
		t.Fatalf("denied launch: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// An authorized launch still returns the URL.
func TestLaunchApp_AuthorizedReturnsURL(t *testing.T) {
	w := launchStatus(t, launchFake{url: "https://payroll.example/"})
	if w.Code != http.StatusOK {
		t.Fatalf("authorized launch: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "https://payroll.example/") {
		t.Fatalf("authorized launch body missing launch_url: %s", w.Body.String())
	}
}

// fakeConsentQuerier scripts the access decision so the handler's own gate is
// what the test observes.
type fakeConsentQuerier struct{ allowed bool }

func (f fakeConsentQuerier) GetApp(context.Context, int64) (*ConsentApp, error) {
	return &ConsentApp{ID: 7, Name: "payroll", LogoURL: "https://cdn.example/p.png"}, nil
}

func (f fakeConsentQuerier) CanAccessApp(context.Context, int64, int64, int64) (bool, error) {
	return f.allowed, nil
}

// /consent/preview returned an app's name, logo and scope labels for ANY app
// id, so a signed-in portal user could enumerate apps they have no access to.
func TestConsentPreview_UnauthorizedAppDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &consentHandler{queryier: fakeConsentQuerier{allowed: false}, tenantID: 1}

	r := gin.New()
	r.Use(withUser(9))
	r.GET("/consent/preview", h.preview)

	req := httptest.NewRequest(http.MethodGet, "/consent/preview?app_id=7&scope=openid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("preview of unauthorized app: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// The legitimate consent prompt must still render.
func TestConsentPreview_AuthorizedAppAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &consentHandler{queryier: fakeConsentQuerier{allowed: true}, tenantID: 1}

	r := gin.New()
	r.Use(withUser(7))
	r.GET("/consent/preview", h.preview)

	req := httptest.NewRequest(http.MethodGet, "/consent/preview?app_id=7&scope=openid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("preview of authorized app: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// consentRouter wires the grant/revoke routes against a scripted access
// decision, over a real consent service so a request that slips past the gate
// shows up as a 200 rather than a nil-receiver panic.
func consentRouter(t *testing.T, allowed bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc := consent.NewService(consentDB(t), nil)
	h := &consentHandler{
		consentSvc: svc,
		queryier:   fakeConsentQuerier{allowed: allowed},
		tenantID:   1,
	}
	r := gin.New()
	r.Use(withUser(9))
	r.POST("/consent", h.grant)
	r.DELETE("/consent/:app_id", h.revoke)
	return r
}

// consentDB creates just the consent table. AutoMigrate is not usable here —
// the model pins `type:text[]`, which sqlite does not have.
func consentDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Exec(`CREATE TABLE mxid_user_app_consent (
		id integer primary key, tenant_id integer, user_id integer,
		app_id integer, scopes text, granted_at datetime, revoked_at datetime)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func postGrant(t *testing.T, r *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"app_id":"7","return_to":"/protocol/oidc/authorize?client_id=x"}`
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// grant took app_id straight from the body, so any signed-in portal user could
// plant a consent row (and mint a login-confirmation token) for an app they
// have no access to.
func TestConsentGrant_UnauthorizedAppDenied(t *testing.T) {
	w := postGrant(t, consentRouter(t, false))
	if w.Code != http.StatusForbidden {
		t.Fatalf("grant for unauthorized app: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// The legitimate consent submit must still succeed.
func TestConsentGrant_AuthorizedAppAllowed(t *testing.T) {
	w := postGrant(t, consentRouter(t, true))
	if w.Code != http.StatusOK {
		t.Fatalf("grant for authorized app: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func deleteConsent(t *testing.T, r *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/consent/7", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// revoke took app_id straight from the path with no access check.
func TestConsentRevoke_UnauthorizedAppDenied(t *testing.T) {
	w := deleteConsent(t, consentRouter(t, false))
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoke for unauthorized app: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// Revoking a consent the user legitimately holds still works (idempotent).
func TestConsentRevoke_AuthorizedAppAllowed(t *testing.T) {
	w := deleteConsent(t, consentRouter(t, true))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke for authorized app: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/consent"
)

// GET /consent/granted echoed GetApp metadata (name, logo, home_url) for every
// consent row the user holds. preview/grant/revoke gate the app id through
// CanAccessApp; list did not, so a row planted before that fix — or an app
// whose access policy was revoked afterwards — kept rendering the app it no
// longer grants access to.
//
// The row itself is the user's own record and stays in the response: the fix
// withholds the app object, not the existence of the grant.

// listConsentQuerier allows exactly one app id so the per-row decision is what
// the test observes.
type listConsentQuerier struct {
	allowedAppID int64
	err          error
}

func (q listConsentQuerier) GetApp(_ context.Context, appID int64) (*ConsentApp, error) {
	return &ConsentApp{
		ID:          appID,
		Name:        "payroll",
		Description: "",
		LogoURL:     "https://cdn.example/p.png",
		HomeURL:     "https://payroll.example/",
	}, nil
}

func (q listConsentQuerier) CanAccessApp(_ context.Context, _, appID, _ int64) (bool, error) {
	if q.err != nil {
		return false, q.err
	}
	return appID == q.allowedAppID, nil
}

type listedConsent struct {
	AppID string      `json:"app_id"`
	App   *ConsentApp `json:"app"`
}

// listGranted seeds one allowed (7) and one no-longer-allowed (8) consent for
// user 9, then calls the handler.
func listGranted(t *testing.T, q ConsentQuerier) (*httptest.ResponseRecorder, []listedConsent) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := consentDB(t)
	// Seeded with SQL, not Service.Grant: Grant mints a snowflake id and this
	// fixture has no generator.
	for i, appID := range []int64{7, 8} {
		if err := db.Exec(`INSERT INTO mxid_user_app_consent
			(id, tenant_id, user_id, app_id, scopes, granted_at, revoked_at)
			VALUES (?, 1, 9, ?, '{openid}', ?, NULL)`,
			i+1, appID, time.Now()).Error; err != nil {
			t.Fatalf("seed consent for app %d: %v", appID, err)
		}
	}
	svc := consent.NewService(db, nil)
	h := &consentHandler{consentSvc: svc, queryier: q, tenantID: 1}
	r := gin.New()
	r.Use(withUser(9))
	r.GET("/consent/granted", h.list)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/consent/granted", nil))
	if w.Code != http.StatusOK {
		return w, nil
	}
	var env struct {
		Data []listedConsent `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return w, env.Data
}

func findRow(t *testing.T, rows []listedConsent, appID string) listedConsent {
	t.Helper()
	for _, r := range rows {
		if r.AppID == appID {
			return r
		}
	}
	t.Fatalf("app_id %s missing from %+v — the consent row belongs to the user and must stay "+
		"visible even when the app metadata is withheld", appID, rows)
	return listedConsent{} //nolint:exhaustruct // unreachable
}

func TestConsentList_WithholdsAppMetadataForUnauthorizedApp(t *testing.T) {
	w, rows := listGranted(t, listConsentQuerier{allowedAppID: 7})

	if len(rows) != 2 {
		t.Fatalf("got %d rows (code=%d body=%s), want both consents listed", len(rows), w.Code, w.Body.String())
	}
	if row := findRow(t, rows, "8"); row.App != nil {
		t.Fatalf("app metadata echoed for an app the user may no longer access: %+v", row.App)
	}
}

// The authorized row must still carry everything the page renders.
func TestConsentList_KeepsAppMetadataForAuthorizedApp(t *testing.T) {
	_, rows := listGranted(t, listConsentQuerier{allowedAppID: 7})

	row := findRow(t, rows, "7")
	if row.App == nil || row.App.Name != "payroll" {
		t.Fatalf("authorized row lost its app metadata: %+v — the access check is over-blocking", row.App)
	}
}

// Fail closed: an unwired querier, or a failing access check, withholds the
// metadata rather than echoing it. Consistent with preview/grant/revoke, which
// refuse outright when there is no querier.
func TestConsentList_FailsClosedWithoutQuerier(t *testing.T) {
	w, rows := listGranted(t, nil)

	if w.Code != http.StatusOK {
		t.Fatalf("list with no querier returned %d, want 200 with metadata withheld (body=%s)",
			w.Code, w.Body.String())
	}
	for _, row := range rows {
		if row.App != nil {
			t.Fatalf("app metadata echoed with no querier wired: %+v — an unavailable check must "+
				"not read as 'allowed'", row.App)
		}
	}
}

func TestConsentList_FailsClosedWhenAccessCheckErrors(t *testing.T) {
	_, rows := listGranted(t, listConsentQuerier{allowedAppID: 7, err: context.DeadlineExceeded})

	for _, row := range rows {
		if row.App != nil {
			t.Fatalf("app metadata echoed after a failed access check: %+v", row.App)
		}
	}
}

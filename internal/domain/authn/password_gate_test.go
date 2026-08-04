package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/errcode"
)

// gateRouter mounts the gate ahead of two routes: one an ordinary business
// endpoint, the other the change-password escape hatch.
func gateRouter(pending bool, mustChange func(ctx context.Context, userID int64) (bool, error)) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Stand in for AuthMiddleware.
		c.Set(CtxUserID, int64(1))
		c.Set(CtxSessionID, "sid")
		c.Set(CtxPwdChangePending, pending)
		c.Next()
	})
	r.Use(PwdGateMiddleware(PwdGateDeps{
		Namespace:  "ns",
		SessionMgr: nil, // only touched on the self-heal path, which is exercised separately
		MustChange: mustChange,
	}))
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	r.GET("/api/v1/portal/apps", ok)
	r.PUT("/api/v1/portal/security/password", ok)
	return r
}

func do(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func bodyCode(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return resp.Code
}

// The whole point: a session that still owes a password change reaches nothing.
func TestPwdGate_BlocksBusinessRoutes(t *testing.T) {
	r := gateRouter(true, func(context.Context, int64) (bool, error) { return true, nil })

	w := do(r, http.MethodGet, "/api/v1/portal/apps")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	// The SPA branches on the number to route to the change-password screen.
	if got := bodyCode(t, w); got != errcode.NumPasswordChangeRequired {
		t.Errorf("code = %d, want %d", got, errcode.NumPasswordChangeRequired)
	}
}

// Blocking everything would leave the user unable to satisfy the demand — the
// gate must leave exactly one way out.
func TestPwdGate_AllowsTheChangePasswordRoute(t *testing.T) {
	r := gateRouter(true, func(context.Context, int64) (bool, error) { return true, nil })

	if w := do(r, http.MethodPut, "/api/v1/portal/security/password"); w.Code != http.StatusOK {
		t.Errorf("the change-password route was blocked: status %d, body %s", w.Code, w.Body)
	}
}

func TestPwdGate_IgnoresSessionsThatOweNothing(t *testing.T) {
	// A nil MustChange proves the lookup is not even reached for the common case.
	r := gateRouter(false, nil)

	if w := do(r, http.MethodGet, "/api/v1/portal/apps"); w.Code != http.StatusOK {
		t.Errorf("an unflagged session was gated: status %d", w.Code)
	}
}

// A lookup failure must not wave the session through: the flag is on because an
// administrator reset the password or the account carries a seeded one.
func TestPwdGate_KeepsBlockingWhenTheLookupFails(t *testing.T) {
	r := gateRouter(true, func(context.Context, int64) (bool, error) {
		return false, errors.New("database is down")
	})

	if w := do(r, http.MethodGet, "/api/v1/portal/apps"); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d — a failed lookup opened the gate", w.Code, http.StatusForbidden)
	}
}

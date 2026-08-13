package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/authz"
)

// POST /users/batch is mounted with authz.Require("user.update") — the right
// floor for enable/disable. But BatchActionDelete reaches the same
// Service.Delete as DELETE /users/:id, which requires user.delete AND a fresh
// step-up (IsHighRiskConsole treats every DELETE as high risk).
//
// The batch route is neither: the method is POST and "/batch" is not a
// high-risk suffix. So an operator holding only user.update, with no recent
// MFA, could delete users in bulk through it — the permission and the sudo
// window both bypassed by choosing a different endpoint for the same
// operation. user.update and user.delete are separate seeded permissions, so
// a role can genuinely hold one without the other.
//
// These tests pin both gates. They stop at the gate: none reaches the service,
// which is nil here — a request that gets past the checks panics, and that is
// itself the signal.

type fakeBindings struct{ perms map[string]struct{} }

func (f fakeBindings) EffectiveBindingsForUser(context.Context, int64, int64) ([]authz.EffectiveBinding, error) {
	return []authz.EffectiveBinding{{
		RoleID:      1,
		Permissions: f.perms,
		Source:      "direct",
		ScopeType:   authz.ScopeGlobal,
	}}, nil
}

func permSet(perms ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		m[p] = struct{}{}
	}
	return m
}

// batchRouter mounts BatchAction with the caller's permissions and step-up
// state. No authz.Require here on purpose: the route-level middleware only ever
// demanded user.update, so what is under test is what the handler adds.
func batchRouter(t *testing.T, h *Handler, perms map[string]struct{}) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, int64(7))
		if perms != nil {
			c.Set(authz.CtxAuthzKey, authz.NewService(fakeBindings{perms: perms}, nil))
		}
		c.Next()
	})
	r.POST("/users/batch", h.BatchAction)
	return r
}

func postBatch(t *testing.T, r *gin.Engine, action string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	body := `{"ids":["1","2"],"action":"` + action + `"}`
	req := httptest.NewRequest(http.MethodPost, "/users/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestBatchDelete_RefusedWithoutUserDeletePermission(t *testing.T) {
	h := NewHandler(nil)
	h.SetStepUpFresh(func(*gin.Context, int64) bool { return true }) // step-up satisfied

	w := postBatch(t, batchRouter(t, h, permSet("user.update")), "delete")

	if w.Code != http.StatusForbidden {
		t.Fatalf("batch delete with only user.update returned %d, want 403 — the batch endpoint "+
			"deletes users without the permission DELETE /users/:id demands", w.Code)
	}
}

func TestBatchDelete_RefusedWithoutFreshStepUp(t *testing.T) {
	h := NewHandler(nil)
	h.SetStepUpFresh(func(*gin.Context, int64) bool { return false })

	w := postBatch(t, batchRouter(t, h, permSet("user.update", "user.delete")), "delete")

	if w.Code != http.StatusForbidden {
		t.Fatalf("batch delete without a fresh step-up returned %d, want 403 — deleting one user "+
			"needs recent MFA, deleting many must not need less", w.Code)
	}
	if !strings.Contains(w.Body.String(), "step-up") {
		t.Fatalf("the refusal must tell the client to step up, got %s", w.Body.String())
	}
}

// TestBatchDelete_RefusedWhenStepUpUnavailable pins the fail-closed direction:
// an unwired checker must not read as "no step-up needed".
func TestBatchDelete_RefusedWhenStepUpUnavailable(t *testing.T) {
	h := NewHandler(nil) // SetStepUpFresh never called

	w := postBatch(t, batchRouter(t, h, permSet("user.update", "user.delete")), "delete")

	if w.Code != http.StatusForbidden {
		t.Fatalf("batch delete with no step-up checker wired returned %d, want 403", w.Code)
	}
}

// TestBatchDelete_RefusedWhenAuthzMissing — no authz service is a denial, not
// a skip.
func TestBatchDelete_RefusedWhenAuthzMissing(t *testing.T) {
	h := NewHandler(nil)
	h.SetStepUpFresh(func(*gin.Context, int64) bool { return true })

	w := postBatch(t, batchRouter(t, h, nil), "delete")

	if w.Code != http.StatusForbidden {
		t.Fatalf("batch delete with no authz service returned %d, want 403", w.Code)
	}
}

// TestBatchEnable_UnaffectedByTheDeleteGates is the other half: the new checks
// must not start demanding user.delete or a sudo window for the bulk actions
// that were always just user.update.
func TestBatchEnable_UnaffectedByTheDeleteGates(t *testing.T) {
	h := NewHandler(nil) // nil service: reaching it panics, which is the assertion
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("batch enable was stopped before the service — the delete-only gates are " +
				"now blocking enable/disable too")
		}
	}()

	_ = postBatch(t, batchRouter(t, h, permSet("user.update")), "enable")
}

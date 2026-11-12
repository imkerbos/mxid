package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/event"
)

// POST /users/batch {"action":"disable"} reaches the same Service.UpdateStatus
// as PUT /users/:id/status, which mayAdministerTarget guards. The batch route
// only ever asked for user.update, so a user_manager could put the
// super_admin's id in the list and disable the sole wildcard holder — locking
// the tenant out through an endpoint that skipped the guard.
//
// Semantics pinned here follow batch delete: a refused id lands in
// resp.Errors and the rest of the batch still applies.

// perUserBindings resolves a different permission set per user id, so a batch
// can mix a privileged target with ordinary ones.
type perUserBindings struct{ byUser map[int64]map[string]struct{} }

func (p perUserBindings) EffectiveBindingsForUser(_ context.Context, _, userID int64) ([]authz.EffectiveBinding, error) {
	return []authz.EffectiveBinding{{
		RoleID:      1,
		Permissions: p.byUser[userID],
		Source:      "direct",
		ScopeType:   authz.ScopeGlobal,
	}}, nil
}

// statusRepo records which ids actually reached the repository.
type statusRepo struct {
	Repository
	mu      sync.Mutex
	updated []int64
}

func (r *statusRepo) UpdateStatus(_ context.Context, id int64, _ int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updated = append(r.updated, id)
	return nil
}

func (r *statusRepo) GetByID(_ context.Context, id int64) (*User, error) {
	return &User{ID: id, TenantID: 1}, nil
}

func batchStatusHandler(repo *statusRepo) *Handler {
	return NewHandler(&Service{repo: repo, eventBus: event.NewBus(nil)})
}

// batchStatusRouter mounts BatchAction with a caller identity and a per-user
// authz view. No authz.Require: what is under test is what the handler adds.
func batchStatusRouter(t *testing.T, h *Handler, callerID int64, byUser map[int64]map[string]struct{}) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, callerID)
		c.Set(authz.CtxAuthzKey, authz.NewService(perUserBindings{byUser: byUser}, nil))
		c.Next()
	})
	r.POST("/users/batch", h.BatchAction)
	return r
}

func postBatchIDs(t *testing.T, r *gin.Engine, action string, ids ...string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	body := `{"ids":["` + strings.Join(ids, `","`) + `"],"action":"` + action + `"}`
	req := httptest.NewRequest(http.MethodPost, "/users/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func decodeBatch(t *testing.T, w *httptest.ResponseRecorder) BatchUsersResponse {
	t.Helper()
	var env struct {
		Data BatchUsersResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode batch response %s: %v", w.Body.String(), err)
	}
	return env.Data
}

// caller 7 is a user_manager; 99 holds the wildcard; 2 and 3 are plain users.
func escalationFixture() map[int64]map[string]struct{} {
	return map[int64]map[string]struct{}{
		7:  permSet("user.update", "user.reset_password"),
		99: permSet("*"),
		2:  permSet(),
		3:  permSet(),
	}
}

func TestBatchDisable_RefusesSuperAdminButAppliesTheRest(t *testing.T) {
	repo := &statusRepo{} //nolint:exhaustruct // zero value is the fixture
	h := batchStatusHandler(repo)

	w := postBatchIDs(t, batchStatusRouter(t, h, 7, escalationFixture()), "disable", "2", "99", "3")

	if w.Code != http.StatusOK {
		t.Fatalf("batch disable returned %d, want 200 with partial success", w.Code)
	}
	res := decodeBatch(t, w)
	if len(res.Errors) != 1 || res.Errors[0].ID != 99 {
		t.Fatalf("want exactly one refused id (99), got errors=%+v — the wildcard holder was "+
			"disabled through the batch endpoint, locking the tenant out", res.Errors)
	}
	if res.Affected != 2 {
		t.Fatalf("affected=%d, want 2 — refusing one id must not abort the batch", res.Affected)
	}
	for _, id := range repo.updated {
		if id == 99 {
			t.Fatal("the super admin's status was written despite the guard")
		}
	}
	if len(repo.updated) != 2 {
		t.Fatalf("repo saw %v, want the two ordinary users only", repo.updated)
	}
}

// Enabling a deliberately disabled high-privilege account is the same
// escalation in reverse, so the enable branch is gated identically.
func TestBatchEnable_RefusesSuperAdmin(t *testing.T) {
	repo := &statusRepo{} //nolint:exhaustruct // zero value is the fixture
	h := batchStatusHandler(repo)

	w := postBatchIDs(t, batchStatusRouter(t, h, 7, escalationFixture()), "enable", "99", "2")

	res := decodeBatch(t, w)
	if len(res.Errors) != 1 || res.Errors[0].ID != 99 {
		t.Fatalf("want the wildcard holder refused, got errors=%+v", res.Errors)
	}
	if res.Affected != 1 {
		t.Fatalf("affected=%d, want 1", res.Affected)
	}
}

// The guard must not turn an ordinary bulk disable into a wall of errors.
func TestBatchDisable_PlainUsersAllSucceed(t *testing.T) {
	repo := &statusRepo{} //nolint:exhaustruct // zero value is the fixture
	h := batchStatusHandler(repo)

	w := postBatchIDs(t, batchStatusRouter(t, h, 7, escalationFixture()), "disable", "2", "3")

	res := decodeBatch(t, w)
	if len(res.Errors) != 0 {
		t.Fatalf("plain-user batch reported errors=%+v, want none", res.Errors)
	}
	if res.Affected != 2 {
		t.Fatalf("affected=%d, want 2", res.Affected)
	}
}

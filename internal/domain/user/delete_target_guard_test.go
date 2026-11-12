package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/event"
)

// DELETE /users/:id was gated only by authz.Require("user.delete") plus the
// step-up middleware — both of which only describe the CALLER. Nothing looked
// at the target, so any role granted user.delete could delete the sole
// wildcard holder: a harder lockout than disabling it, since the account is
// gone rather than switched off.
//
// The seeded user_manager role does NOT hold user.delete (migration 000016),
// so no shipped role reaches this today; a custom role granted user.delete
// does, which is exactly the case the guard exists for.
//
// POST /users/batch {"action":"delete"} is the same operation by another door:
// it already checks the caller's user.delete and step-up freshness, but had no
// per-id target guard — unlike its enable/disable branch.

// deleteRepo records which ids actually reached the repository.
type deleteRepo struct {
	Repository
	mu      sync.Mutex
	deleted []int64
}

func (r *deleteRepo) GetByID(_ context.Context, id int64) (*User, error) {
	return &User{ID: id, TenantID: 1}, nil
}

func (r *deleteRepo) SoftDeleteIdentitiesByUser(context.Context, int64) error { return nil }

func (r *deleteRepo) Delete(_ context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, id)
	return nil
}

func deleteHandler(repo *deleteRepo) *Handler {
	h := NewHandler(&Service{repo: repo, eventBus: event.NewBus(nil)})
	h.SetStepUpFresh(func(*gin.Context, int64) bool { return true })
	return h
}

// deleteFixture: caller 7 holds user.delete without the wildcard; 98 and 99
// hold the wildcard; 2 and 3 are plain users.
func deleteFixture() map[int64]map[string]struct{} {
	return map[int64]map[string]struct{}{
		7:  permSet("user.read", "user.update", "user.delete"),
		98: permSet("*"),
		99: permSet("*"),
		2:  permSet(),
		3:  permSet(),
	}
}

// deleteRouter mounts Delete and BatchAction with a caller identity and a
// per-user authz view. A nil byUser means no authz service in context.
func deleteRouter(t *testing.T, h *Handler, callerID int64, byUser map[int64]map[string]struct{}) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, callerID)
		if byUser != nil {
			c.Set(authz.CtxAuthzKey, authz.NewService(perUserBindings{byUser: byUser}, nil))
		}
		c.Next()
	})
	r.DELETE("/users/:id", h.Delete)
	r.POST("/users/batch", h.BatchAction)
	return r
}

func deleteUser(t *testing.T, r *gin.Engine, target int64) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/users/"+strconv.FormatInt(target, 10), nil)
	r.ServeHTTP(w, req)
	return w
}

func TestDeleteUser_RefusesSuperAdminTarget(t *testing.T) {
	repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
	w := deleteUser(t, deleteRouter(t, deleteHandler(repo), 7, deleteFixture()), 99)

	if w.Code != http.StatusForbidden {
		t.Fatalf("deleting the wildcard holder returned %d, want 403 — a role holding user.delete "+
			"could erase the only super admin, locking the tenant out for good", w.Code)
	}
	if len(repo.deleted) != 0 {
		t.Fatalf("repo saw deletes %v despite the guard", repo.deleted)
	}
}

func TestDeleteUser_StillDeletesOrdinaryUser(t *testing.T) {
	repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
	w := deleteUser(t, deleteRouter(t, deleteHandler(repo), 7, deleteFixture()), 2)

	if w.Code != http.StatusOK {
		t.Fatalf("deleting an ordinary user returned %d, want 200 — the escalation guard is "+
			"blocking legitimate work (body=%s)", w.Code, w.Body.String())
	}
	if len(repo.deleted) != 1 || repo.deleted[0] != 2 {
		t.Fatalf("repo saw %v, want [2]", repo.deleted)
	}
}

func TestDeleteUser_SuperAdminStillDeletesAnyone(t *testing.T) {
	for name, target := range map[string]int64{"another super admin": 98, "an ordinary user": 2} {
		t.Run(name, func(t *testing.T) {
			repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
			w := deleteUser(t, deleteRouter(t, deleteHandler(repo), 99, deleteFixture()), target)
			if w.Code != http.StatusOK {
				t.Fatalf("super_admin deleting %s returned %d, want 200 — a wildcard holder must "+
					"keep full reach", name, w.Code)
			}
		})
	}
}

func TestDeleteUser_RefusesWhenAuthzMissing(t *testing.T) {
	repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
	w := deleteUser(t, deleteRouter(t, deleteHandler(repo), 7, nil), 2)

	if w.Code != http.StatusForbidden {
		t.Fatalf("delete with no authz service returned %d, want 403 — an unavailable engine must "+
			"not read as 'nothing to check'", w.Code)
	}
	if len(repo.deleted) != 0 {
		t.Fatalf("repo saw deletes %v with no authz engine", repo.deleted)
	}
}

func TestDeleteUser_RefusesWhenCallerUnauthenticated(t *testing.T) {
	repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
	w := deleteUser(t, deleteRouter(t, deleteHandler(repo), 0, deleteFixture()), 2)

	if w.Code != http.StatusForbidden {
		t.Fatalf("delete with no caller identity returned %d, want 403", w.Code)
	}
}

// --- the batch door to the same operation -----------------------------------

func TestBatchDelete_RefusesSuperAdminButAppliesTheRest(t *testing.T) {
	repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
	r := deleteRouter(t, deleteHandler(repo), 7, deleteFixture())

	w := postBatchIDs(t, r, "delete", "2", "99", "3")

	if w.Code != http.StatusOK {
		t.Fatalf("batch delete returned %d, want 200 with partial success", w.Code)
	}
	res := decodeBatch(t, w)
	if len(res.Errors) != 1 || res.Errors[0].ID != 99 {
		t.Fatalf("want exactly one refused id (99), got errors=%+v — the wildcard holder was "+
			"deleted through the batch endpoint", res.Errors)
	}
	if res.Affected != 2 {
		t.Fatalf("affected=%d, want 2 — refusing one id must not abort the batch", res.Affected)
	}
	for _, id := range repo.deleted {
		if id == 99 {
			t.Fatal("the super admin was deleted despite the guard")
		}
	}
	if len(repo.deleted) != 2 {
		t.Fatalf("repo saw %v, want the two ordinary users only", repo.deleted)
	}
}

// The guard must not turn an ordinary bulk delete into a wall of errors.
func TestBatchDelete_PlainUsersAllSucceed(t *testing.T) {
	repo := &deleteRepo{} //nolint:exhaustruct // zero value is the fixture
	r := deleteRouter(t, deleteHandler(repo), 7, deleteFixture())

	res := decodeBatch(t, postBatchIDs(t, r, "delete", "2", "3"))

	if len(res.Errors) != 0 {
		t.Fatalf("plain-user batch delete reported errors=%+v, want none", res.Errors)
	}
	if res.Affected != 2 {
		t.Fatalf("affected=%d, want 2", res.Affected)
	}
}

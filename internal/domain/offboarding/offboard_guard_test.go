package offboarding

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/authz"
)

// POST /users/:id/offboard is gated only by the caller's own user.update,
// which the seeded user_manager role holds globally. Nothing looked at the
// TARGET, so a user-desk role could run the departure flow on the super_admin:
// account disabled, back-channel logout, every session killed. Same effect as
// the admin lock this guard already refuses. These tests pin the shared target
// guard on that route.
//
// They stop at the gate: the handler's service is nil, so a request that gets
// past the guard panics — which is how the "still allowed" cases assert the
// guard did not over-block.

type offboardGuardBindings struct {
	byUser map[int64]map[string]struct{}
	err    error
}

func (b offboardGuardBindings) EffectiveBindingsForUser(_ context.Context, _ int64, userID int64) ([]authz.EffectiveBinding, error) {
	if b.err != nil {
		return nil, b.err
	}
	perms, ok := b.byUser[userID]
	if !ok {
		return nil, nil
	}
	return []authz.EffectiveBinding{{
		RoleID:      1,
		Permissions: perms,
		Source:      "direct",
		ScopeType:   authz.ScopeGlobal,
	}}, nil
}

const (
	ogCallerUserManager int64 = 11
	ogCallerSuperAdmin  int64 = 12
	ogTargetSuperAdmin  int64 = 90
	ogTargetPlainUser   int64 = 91
)

func offboardGuardFixture() map[int64]map[string]struct{} {
	return map[int64]map[string]struct{}{
		// Mirrors the seeded user_manager role (migration 000016).
		ogCallerUserManager: {
			"user.read":           {},
			"user.update":         {},
			"user.session.manage": {},
		},
		ogCallerSuperAdmin: {"*": {}},
		ogTargetSuperAdmin: {"*": {}},
		// ogTargetPlainUser deliberately absent: holds nothing.
	}
}

func offboardGuardRouter(t *testing.T, callerID int64, binds *offboardGuardBindings) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewHandler(nil, 1)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, callerID)
		if binds != nil {
			c.Set(authz.CtxAuthzKey, authz.NewService(*binds, nil))
		}
		c.Next()
	})
	r.POST("/users/:id/offboard", h.Offboard)
	return r
}

func offboard(t *testing.T, r *gin.Engine, target int64) (w *httptest.ResponseRecorder, reachedService bool) {
	t.Helper()
	w = httptest.NewRecorder()
	defer func() {
		if rec := recover(); rec != nil {
			reachedService = true
		}
	}()
	req := httptest.NewRequest(http.MethodPost, "/users/"+strconv.FormatInt(target, 10)+"/offboard", nil)
	r.ServeHTTP(w, req)
	return w, false
}

func TestOffboard_UserManagerCannotTargetSuperAdmin(t *testing.T) {
	binds := &offboardGuardBindings{byUser: offboardGuardFixture()}
	w, reached := offboard(t, offboardGuardRouter(t, ogCallerUserManager, binds), ogTargetSuperAdmin)

	if reached {
		t.Fatal("user_manager offboarding the super_admin reached the service — disabling the only " +
			"wildcard holder and killing its sessions locks the tenant out")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestOffboard_UserManagerStillOffboardsOrdinaryUsers(t *testing.T) {
	binds := &offboardGuardBindings{byUser: offboardGuardFixture()}
	w, reached := offboard(t, offboardGuardRouter(t, ogCallerUserManager, binds), ogTargetPlainUser)

	if !reached {
		t.Fatalf("user_manager offboarding an ordinary user was stopped with %d — the escalation "+
			"guard is blocking the role's legitimate work", w.Code)
	}
}

func TestOffboard_SuperAdminStillOffboardsAnyone(t *testing.T) {
	for name, target := range map[string]int64{
		"another super admin": ogTargetSuperAdmin,
		"an ordinary user":    ogTargetPlainUser,
	} {
		t.Run(name, func(t *testing.T) {
			binds := &offboardGuardBindings{byUser: offboardGuardFixture()}
			w, reached := offboard(t, offboardGuardRouter(t, ogCallerSuperAdmin, binds), target)
			if !reached {
				t.Fatalf("super_admin offboarding %s was stopped with %d — a wildcard holder must "+
					"keep full reach", name, w.Code)
			}
		})
	}
}

func TestOffboard_RefusesWhenAuthzMissing(t *testing.T) {
	w, reached := offboard(t, offboardGuardRouter(t, ogCallerUserManager, nil), ogTargetPlainUser)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("offboard with no authz service in context: reached=%v code=%d, want blocked with "+
			"403 — an unavailable engine must not read as 'nothing to check'", reached, w.Code)
	}
}

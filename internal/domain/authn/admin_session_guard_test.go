package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/authz"
)

// DELETE /users/:id/sessions is gated only by the caller's own
// user.session.manage, which the seeded user_manager role holds globally.
// Nothing looked at the TARGET, so a user-desk role could sign the super_admin
// out of everything, repeatedly — a denial of service on the only wildcard
// holder. These tests pin the shared target guard on that route.
//
// They stop at the gate: the handler's session manager is nil, so a request
// that gets past the guard panics — which is how the "still allowed" cases
// assert the guard did not over-block.

type sessionGuardBindings struct {
	byUser map[int64]map[string]struct{}
	err    error
}

func (b sessionGuardBindings) EffectiveBindingsForUser(_ context.Context, _ int64, userID int64) ([]authz.EffectiveBinding, error) {
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
	sgCallerUserManager int64 = 11
	sgCallerSuperAdmin  int64 = 12
	sgTargetSuperAdmin  int64 = 90
	sgTargetPlainUser   int64 = 91
)

func sessionGuardFixture() map[int64]map[string]struct{} {
	return map[int64]map[string]struct{}{
		// Mirrors the seeded user_manager role (migration 000016).
		sgCallerUserManager: {
			"user.read":           {},
			"user.reset_password": {},
			"user.mfa.manage":     {},
			"user.session.manage": {},
			"user.lock":           {},
		},
		sgCallerSuperAdmin: {"*": {}},
		sgTargetSuperAdmin: {"*": {}},
		// sgTargetPlainUser deliberately absent: holds nothing.
	}
}

func sessionGuardRouter(t *testing.T, callerID int64, binds *sessionGuardBindings) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewAdminSessionHandler(nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(CtxUserID, callerID)
		if binds != nil {
			c.Set(authz.CtxAuthzKey, authz.NewService(*binds, nil))
		}
		c.Next()
	})
	r.DELETE("/users/:id/sessions", h.revokeAll)
	return r
}

func revokeAllSessions(t *testing.T, r *gin.Engine, target int64) (w *httptest.ResponseRecorder, reachedService bool) {
	t.Helper()
	w = httptest.NewRecorder()
	defer func() {
		if rec := recover(); rec != nil {
			reachedService = true
		}
	}()
	req := httptest.NewRequest(http.MethodDelete, "/users/"+strconv.FormatInt(target, 10)+"/sessions", nil)
	r.ServeHTTP(w, req)
	return w, false
}

func TestRevokeAllSessions_UserManagerCannotTargetSuperAdmin(t *testing.T) {
	binds := &sessionGuardBindings{byUser: sessionGuardFixture()}
	w, reached := revokeAllSessions(t, sessionGuardRouter(t, sgCallerUserManager, binds), sgTargetSuperAdmin)

	if reached {
		t.Fatal("user_manager revoking every super_admin session reached the service — a user-desk " +
			"role can keep the only wildcard holder logged out indefinitely")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestRevokeAllSessions_UserManagerStillRevokesOrdinaryUsers(t *testing.T) {
	binds := &sessionGuardBindings{byUser: sessionGuardFixture()}
	w, reached := revokeAllSessions(t, sessionGuardRouter(t, sgCallerUserManager, binds), sgTargetPlainUser)

	if !reached {
		t.Fatalf("user_manager revoking an ordinary user's sessions was stopped with %d — the "+
			"escalation guard is blocking the role's legitimate work", w.Code)
	}
}

func TestRevokeAllSessions_SuperAdminStillRevokesAnyone(t *testing.T) {
	for name, target := range map[string]int64{
		"another super admin": sgTargetSuperAdmin,
		"an ordinary user":    sgTargetPlainUser,
	} {
		t.Run(name, func(t *testing.T) {
			binds := &sessionGuardBindings{byUser: sessionGuardFixture()}
			w, reached := revokeAllSessions(t, sessionGuardRouter(t, sgCallerSuperAdmin, binds), target)
			if !reached {
				t.Fatalf("super_admin revoking sessions of %s was stopped with %d — a wildcard "+
					"holder must keep full reach", name, w.Code)
			}
		})
	}
}

func TestRevokeAllSessions_RefusesWhenAuthzMissing(t *testing.T) {
	w, reached := revokeAllSessions(t, sessionGuardRouter(t, sgCallerUserManager, nil), sgTargetPlainUser)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("revoke with no authz service in context: reached=%v code=%d, want blocked with 403 — "+
			"an unavailable engine must not read as 'nothing to check'", reached, w.Code)
	}
}

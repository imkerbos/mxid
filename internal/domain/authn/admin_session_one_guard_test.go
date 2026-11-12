package authn

import (
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/session"
)

// DELETE /users/:id/sessions/:sid has an ownership guard (the sid must belong
// to :id) but no TARGET guard, so the per-session route was the one-at-a-time
// version of the hole already closed on revokeAll: the seeded user_manager
// holds user.session.manage globally and could sign the super_admin out
// session by session.
//
// Same stop-at-the-gate technique as the revokeAll tests: the session manager
// is nil, so a request that gets past the guard panics — which is how the
// "still allowed" cases assert the guard did not over-block.

func sessionOneRouter(t *testing.T, callerID int64, binds *sessionGuardBindings) *gin.Engine {
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
	r.DELETE("/users/:id/sessions/:sid", h.revokeOne)
	return r
}

func revokeOneSession(t *testing.T, r *gin.Engine, target int64) (w *httptest.ResponseRecorder, reachedService bool) {
	t.Helper()
	w = httptest.NewRecorder()
	defer func() {
		if rec := recover(); rec != nil {
			reachedService = true
		}
	}()
	url := "/users/" + strconv.FormatInt(target, 10) + "/sessions/abc?namespace=" +
		neturl.QueryEscape(session.NamespaceConsole)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, url, nil))
	return w, false
}

func TestRevokeOneSession_UserManagerCannotTargetSuperAdmin(t *testing.T) {
	binds := &sessionGuardBindings{byUser: sessionGuardFixture()}
	w, reached := revokeOneSession(t, sessionOneRouter(t, sgCallerUserManager, binds), sgTargetSuperAdmin)

	if reached {
		t.Fatal("user_manager revoking a super_admin session reached the service — the per-session " +
			"route is the same denial of service as revokeAll, one request at a time")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestRevokeOneSession_UserManagerStillRevokesOrdinaryUsers(t *testing.T) {
	binds := &sessionGuardBindings{byUser: sessionGuardFixture()}
	w, reached := revokeOneSession(t, sessionOneRouter(t, sgCallerUserManager, binds), sgTargetPlainUser)

	if !reached {
		t.Fatalf("user_manager revoking an ordinary user's session was stopped with %d — the "+
			"escalation guard is blocking the role's legitimate work", w.Code)
	}
}

func TestRevokeOneSession_SuperAdminStillRevokesAnyone(t *testing.T) {
	for name, target := range map[string]int64{
		"another super admin": sgTargetSuperAdmin,
		"an ordinary user":    sgTargetPlainUser,
	} {
		t.Run(name, func(t *testing.T) {
			binds := &sessionGuardBindings{byUser: sessionGuardFixture()}
			w, reached := revokeOneSession(t, sessionOneRouter(t, sgCallerSuperAdmin, binds), target)
			if !reached {
				t.Fatalf("super_admin revoking a session of %s was stopped with %d — a wildcard "+
					"holder must keep full reach", name, w.Code)
			}
		})
	}
}

func TestRevokeOneSession_RefusesWhenAuthzMissing(t *testing.T) {
	w, reached := revokeOneSession(t, sessionOneRouter(t, sgCallerUserManager, nil), sgTargetPlainUser)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("revoke-one with no authz service in context: reached=%v code=%d, want blocked "+
			"with 403", reached, w.Code)
	}
}

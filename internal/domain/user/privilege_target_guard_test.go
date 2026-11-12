package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/authz"
)

// PUT /users/:id/password, DELETE /users/:id/mfa/:type and POST /users/:id/lock
// are gated only by the caller's own permission (user.reset_password /
// user.mfa.manage / user.lock). Nothing looked at the TARGET. The seeded
// user_manager role holds all three, globally, so it could: drop the
// super_admin's TOTP, reset its password to a known value, and sign in as it.
// Privilege escalation to full tenant control from a user-desk role.
//
// The role-grant path already guards this (permission.checkAssignAllowed): a
// caller may not hand out a permission it does not hold, and only a wildcard
// holder may touch super_admin. These tests pin the same semantics on the
// three user-administration endpoints.
//
// They stop at the gate: the handler's service is nil, so a request that gets
// past the guard panics — which is exactly how the "still allowed" cases
// assert that the guard did not over-block.

// targetBindings resolves a different permission set per user, so a test can
// describe a caller and a target at once. A user absent from the map holds
// nothing (an ordinary end user).
type targetBindings struct {
	byUser map[int64]map[string]struct{}
	err    error
}

func (t targetBindings) EffectiveBindingsForUser(_ context.Context, _ int64, userID int64) ([]authz.EffectiveBinding, error) {
	if t.err != nil {
		return nil, t.err
	}
	perms, ok := t.byUser[userID]
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
	callerUserManager int64 = 11
	callerSuperAdmin  int64 = 12
	targetSuperAdmin  int64 = 90
	targetPlainUser   int64 = 91
)

// userManagerPerms mirrors the seeded user_manager role (migration 000016):
// global, unscoped, and holding exactly the three permissions this guard
// protects plus session management.
func userManagerPerms() map[string]struct{} {
	return permSet("user.read", "user.reset_password", "user.mfa.manage", "user.session.manage", "user.lock")
}

func guardFixture() map[int64]map[string]struct{} {
	return map[int64]map[string]struct{}{
		callerUserManager: userManagerPerms(),
		callerSuperAdmin:  permSet("*"),
		targetSuperAdmin:  permSet("*"),
		// targetPlainUser deliberately absent: holds nothing.
	}
}

// guardRouter mounts the three guarded handlers with the given caller identity
// and binding resolver. A nil resolver means no authz service in context.
func guardRouter(t *testing.T, h *Handler, callerID int64, binds *targetBindings) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, callerID)
		if binds != nil {
			c.Set(authz.CtxAuthzKey, authz.NewService(*binds, nil))
		}
		c.Next()
	})
	r.PUT("/users/:id/password", h.ResetPassword)
	r.DELETE("/users/:id/mfa/:type", h.DeleteMFA)
	r.POST("/users/:id/lock", h.LockUser)
	r.PUT("/users/:id", h.Update)
	r.PUT("/users/:id/status", h.UpdateStatus)
	return r
}

// do runs the request and reports whether it reached the (nil) service. The
// nil-pointer panic is the signal that nothing stopped the request: recovering
// it here keeps one failing case from taking the whole test binary down, so a
// single run shows every direction of the guard at once.
func do(t *testing.T, r *gin.Engine, method, path, body string) (w *httptest.ResponseRecorder, reachedService bool) {
	t.Helper()
	w = httptest.NewRecorder()
	defer func() {
		if rec := recover(); rec != nil {
			reachedService = true
		}
	}()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w, false
}

func resetPassword(t *testing.T, r *gin.Engine, target int64) (*httptest.ResponseRecorder, bool) {
	return do(t, r, http.MethodPut, "/users/"+itoa(target)+"/password", `{"new_password":"Str0ngPass!1"}`)
}

func deleteTOTP(t *testing.T, r *gin.Engine, target int64) (*httptest.ResponseRecorder, bool) {
	return do(t, r, http.MethodDelete, "/users/"+itoa(target)+"/mfa/totp", "")
}

func lockUser(t *testing.T, r *gin.Engine, target int64) (*httptest.ResponseRecorder, bool) {
	return do(t, r, http.MethodPost, "/users/"+itoa(target)+"/lock", `{"reason":"test"}`)
}

// changeEmail is the second takeover route: UpdateUserRequest accepts Email,
// so rewriting the super_admin's address and then using password recovery
// reaches the same place as resetting its password directly.
func changeEmail(t *testing.T, r *gin.Engine, target int64) (*httptest.ResponseRecorder, bool) {
	return do(t, r, http.MethodPut, "/users/"+itoa(target), `{"email":"attacker@example.test"}`)
}

// disableAccount uses PUT /users/:id/status with status 3 — equivalent in
// effect to the admin lock, and reachable with user.update instead of
// user.lock.
func disableAccount(t *testing.T, r *gin.Engine, target int64) (*httptest.ResponseRecorder, bool) {
	return do(t, r, http.MethodPut, "/users/"+itoa(target)+"/status", `{"status":3}`)
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

// --- the account-takeover chain, step by step -------------------------------

func TestUserManager_CannotDeleteSuperAdminMFA(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture()}
	w, reached := deleteTOTP(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetSuperAdmin)

	if reached {
		t.Fatal("user_manager stripping the super_admin's TOTP reached the service — this is step " +
			"one of a full account takeover")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestUserManager_CannotResetSuperAdminPassword(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture()}
	w, reached := resetPassword(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetSuperAdmin)

	if reached {
		t.Fatal("user_manager resetting the super_admin's password reached the service — the " +
			"takeover is one login away")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestUserManager_CannotLockSuperAdmin(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture()}
	w, reached := lockUser(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetSuperAdmin)

	if reached {
		t.Fatal("user_manager locking the super_admin reached the service — locking out the only " +
			"wildcard holder is a denial of service on the tenant")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestUserManager_CannotChangeSuperAdminEmail(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture()}
	w, reached := changeEmail(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetSuperAdmin)

	if reached {
		t.Fatal("user_manager rewriting the super_admin's email reached the service — password " +
			"recovery then hands over the account, same destination as a direct password reset")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestUserManager_CannotDisableSuperAdmin(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture()}
	w, reached := disableAccount(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetSuperAdmin)

	if reached {
		t.Fatal("user_manager setting the super_admin to status=3 reached the service — disabling " +
			"the only wildcard holder locks the tenant out, exactly like the admin lock")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

// --- the guard must not break the job the role exists to do -----------------

func TestUserManager_StillAdministersOrdinaryUsers(t *testing.T) {
	cases := []struct {
		name string
		call func(*testing.T, *gin.Engine, int64) (*httptest.ResponseRecorder, bool)
	}{
		{"reset password", resetPassword},
		{"delete mfa", deleteTOTP},
		{"lock", lockUser},
		{"change email", changeEmail},
		{"disable", disableAccount},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binds := &targetBindings{byUser: guardFixture()}
			w, reached := tc.call(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetPlainUser)
			if !reached {
				t.Fatalf("user_manager %s on an ordinary user was stopped with %d — the escalation "+
					"guard is blocking the role's legitimate work", tc.name, w.Code)
			}
		})
	}
}

func TestSuperAdmin_StillAdministersAnyone(t *testing.T) {
	ops := map[string]func(*testing.T, *gin.Engine, int64) (*httptest.ResponseRecorder, bool){
		"reset password": resetPassword,
		"delete mfa":     deleteTOTP,
		"lock":           lockUser,
		"change email":   changeEmail,
		"disable":        disableAccount,
	}
	targets := map[string]int64{"another super admin": targetSuperAdmin, "an ordinary user": targetPlainUser}
	for opName, op := range ops {
		for name, target := range targets {
			t.Run(opName+" on "+name, func(t *testing.T) {
				binds := &targetBindings{byUser: guardFixture()}
				w, reached := op(t, guardRouter(t, NewHandler(nil), callerSuperAdmin, binds), target)
				if !reached {
					t.Fatalf("super_admin doing %s on %s was stopped with %d — a wildcard holder "+
						"must keep full reach", opName, name, w.Code)
				}
			})
		}
	}
}

// --- fail closed ------------------------------------------------------------

func TestTargetGuard_RefusesWhenAuthzMissing(t *testing.T) {
	w, reached := resetPassword(t, guardRouter(t, NewHandler(nil), callerUserManager, nil), targetPlainUser)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("reset with no authz service in context: reached=%v code=%d, want blocked with 403 — "+
			"an unavailable engine must not read as 'nothing to check'", reached, w.Code)
	}
}

func TestTargetGuard_RefusesWhenCallerUnauthenticated(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture()}
	w, reached := resetPassword(t, guardRouter(t, NewHandler(nil), 0, binds), targetPlainUser)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("reset with no caller identity: reached=%v code=%d, want blocked with 403", reached, w.Code)
	}
}

func TestTargetGuard_RefusesWhenLookupFails(t *testing.T) {
	binds := &targetBindings{byUser: guardFixture(), err: context.DeadlineExceeded}
	w, reached := resetPassword(t, guardRouter(t, NewHandler(nil), callerUserManager, binds), targetPlainUser)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("reset with a failing permission lookup: reached=%v code=%d, want blocked with 403", reached, w.Code)
	}
}

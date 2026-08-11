package authn

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/errcode"
	"github.com/imkerbos/mxid/pkg/session"
)

// PwdGateDeps are the collaborators the forced-password-change gate needs.
type PwdGateDeps struct {
	Namespace  string
	SessionMgr *session.Manager
	// MustChange reports whether the user still owes a password change — used
	// to clear a stale flag once they have chosen one.
	MustChange func(ctx context.Context, userID int64) (bool, error)
}

// pwdAllowedPathFragment is the only surface a pending user may reach. Console
// and portal both mount self-service password change at /security/password, so
// one fragment covers both.
const pwdAllowedPathFragment = "/security/password"

// PwdGateMiddleware blocks a session flagged PwdChangePending from every route
// except changing the password. It must run AFTER AuthMiddleware, which puts
// the flag in the request context.
//
// # Why this exists
//
// `must_change_pwd` was written by every administrative password reset, and
// documented as forcing the user to pick a new one on their next login. Nothing
// read it. The only consumer in the codebase was a badge on the console user
// detail page, so an administrator resetting a compromised account's password
// believed they had forced a change that never happened.
//
// It is also what makes the seeded administrator account safe: that account
// ships with a password published in a public repository, and until the gate
// existed, knowing it was enough to have the whole console.
//
// Cost: for the overwhelming common case (not pending) it returns immediately.
// Only a pending session triggers the lookup, and that path self-heals — once
// the password has been changed the flag is cleared and the lookup never
// recurs.
func PwdGateMiddleware(d PwdGateDeps) gin.HandlerFunc {
	return obligationGate{
		namespace: d.Namespace,
		ctxFlag:   CtxPwdChangePending,
		stillOwes: func(ctx context.Context, userID int64) (bool, error) {
			if d.MustChange == nil {
				return true, nil
			}
			return d.MustChange(ctx, userID)
		},
		clearFlag: d.SessionMgr.SetPwdChangePending,
		code:      errcode.NumPasswordChangeRequired,
		message:   "password change required",
	}.handler()
}

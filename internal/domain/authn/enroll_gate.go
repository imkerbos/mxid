package authn

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/session"
)

// EnrollGateDeps are the collaborators the mandatory-MFA-enrollment gate needs.
type EnrollGateDeps struct {
	Namespace  string
	SessionMgr *session.Manager
	// HasMFA reports whether the user has a factor enrolled — used to clear a
	// stale pending flag once they bind one.
	HasMFA func(ctx context.Context, userID int64) (bool, error)
}

// enrollAllowedPathFragment is the only surface a pending user may reach — the
// MFA enrollment endpoints. Matched as a substring of the gin route template.
const enrollAllowedPathFragment = "/security/mfa"

// EnrollGateMiddleware blocks a session flagged MFAEnrollPending from every
// route except MFA enrollment, until the user binds a factor. It must run AFTER
// AuthMiddleware (which sets the pending flag in context).
//
// Cost: for the overwhelming common case (not pending) it returns immediately
// with no extra work. Only a pending session triggers the HasMFA lookup, and
// that path self-heals — once a factor is detected the flag is cleared so the
// lookup never recurs.
func EnrollGateMiddleware(d EnrollGateDeps) gin.HandlerFunc {
	return obligationGate{
		namespace: d.Namespace,
		ctxFlag:   CtxMFAEnrollPending,
		// HasMFA answers the opposite question, so invert it: having a factor
		// means the enrollment is no longer owed.
		stillOwes: func(ctx context.Context, userID int64) (bool, error) {
			if d.HasMFA == nil {
				return true, nil
			}
			has, err := d.HasMFA(ctx, userID)
			return !has, err
		},
		clearFlag: d.SessionMgr.SetEnrollPending,
		code:      CodeMFAEnrollRequired,
		message:   "mfa enrollment required",
	}.handler()
}

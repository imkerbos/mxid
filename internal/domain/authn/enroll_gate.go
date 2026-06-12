package authn

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/response"
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
	return func(c *gin.Context) {
		if !c.GetBool(CtxMFAEnrollPending) {
			c.Next()
			return
		}

		// The user may have just bound a factor on a prior request — clear the
		// stale flag and let them through.
		if d.HasMFA != nil {
			if ok, err := d.HasMFA(c.Request.Context(), c.GetInt64(CtxUserID)); err == nil && ok {
				_ = d.SessionMgr.SetEnrollPending(c.Request.Context(), d.Namespace, c.GetString(CtxSessionID), false)
				c.Next()
				return
			}
		}

		// Still no factor — only the enrollment surface is reachable.
		if strings.Contains(c.FullPath(), enrollAllowedPathFragment) {
			c.Next()
			return
		}

		response.Forbidden(c, CodeMFAEnrollRequired, "mfa enrollment required")
		c.Abort()
	}
}

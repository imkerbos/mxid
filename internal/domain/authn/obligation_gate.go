package authn

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/response"
)

// An obligation gate holds a session until its owner settles a debt: pick a new
// password, bind an MFA factor. Every such gate has the same four moves — skip
// when nothing is owed, self-heal a flag the user already settled, allow the
// surfaces where debts get settled, otherwise refuse.
//
// # Why this is one function and not one per gate
//
// It used to be one per gate, and the two copies diverged in the only place it
// mattered: each allowed just its own remediation surface. A session owing both
// a password change and an MFA enrollment was then refused at both — the
// enrollment call by the password gate, the password call by the enrollment
// gate. The user saw two demands and could satisfy neither, with no way out but
// an administrator editing a flag in the database. A restored account lands in
// exactly that state.
//
// Sharing the body means a third obligation cannot reintroduce that bug by
// forgetting to permit the other two: allowance is computed in one place, over
// one list.
type obligationGate struct {
	// namespace and sessionMgr locate the session whose flag gets cleared.
	namespace string
	// ctxFlag is the request-context key AuthMiddleware sets when this debt is
	// outstanding for the session.
	ctxFlag string
	// stillOwes re-checks the debt against durable state. Optional; nil means
	// trust the session flag. Returning false clears the flag and lets the
	// request through, so the gate stops costing a lookup once settled.
	stillOwes func(ctx context.Context, userID int64) (bool, error)
	// clearFlag writes the settled state back to the session.
	clearFlag func(ctx context.Context, namespace, sessionID string, pending bool) error
	// code and message are what a refused caller receives. The SPA switches on
	// the code to decide which blocking screen to show.
	code    int
	message string
}

// remediationPathFragments are the self-service surfaces every obligation gate
// permits, whatever debt it is enforcing. Matched as substrings of the gin
// route template. A gate that allowed only its own would deadlock against the
// others — see the type comment above.
//
// Adding an obligation means adding its remediation surface here, or that
// obligation becomes unsatisfiable whenever it coincides with another.
var remediationPathFragments = []string{
	pwdAllowedPathFragment,
	enrollAllowedPathFragment,
}

// isRemediationPath reports whether a route is one of the surfaces a blocked
// session must always be able to reach.
func isRemediationPath(fullPath string) bool {
	for _, fragment := range remediationPathFragments {
		if strings.Contains(fullPath, fragment) {
			return true
		}
	}
	return false
}

// handler builds the gin middleware. It must run AFTER AuthMiddleware, which is
// what puts the pending flag in the request context.
//
// Cost: for the overwhelming common case (nothing owed) it returns immediately
// with no extra work. Only a pending session triggers the lookup, and that path
// self-heals.
func (g obligationGate) handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !c.GetBool(g.ctxFlag) {
			c.Next()
			return
		}

		// They may have settled it on a prior request — clear the stale flag
		// and let them through. Checked BEFORE the path allowance so that the
		// very request which settles the debt still passes below, and the one
		// after it comes back clean.
		if g.stillOwes != nil {
			if owes, err := g.stillOwes(c.Request.Context(), c.GetInt64(CtxUserID)); err == nil && !owes {
				_ = g.clearFlag(c.Request.Context(), g.namespace, c.GetString(CtxSessionID), false)
				c.Next()
				return
			}
		}

		if isRemediationPath(c.FullPath()) {
			c.Next()
			return
		}

		response.Forbidden(c, g.code, g.message)
		c.Abort()
	}
}

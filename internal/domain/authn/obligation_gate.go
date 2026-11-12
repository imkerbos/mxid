package authn

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
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
	// namespace, with the request's session id, locates the session whose flag
	// gets cleared.
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
	// peerNamespaces are the other namespaces holding sessions of the SAME
	// user that carry the same flag. One login writes both an SPA session and
	// the shared protocol session the SSO bridge hands to SAML/CAS/OIDC, and
	// Manager.Create stamps the obligation on both. Clearing only the SPA one
	// leaves the protocol one flagged, which the protocol resolver reports as
	// no session at all — so the user who just settled the debt is sent
	// through authentication again at the next RP hop.
	peerNamespaces []string
	// sessionsByUser lists one user's sessions in a namespace. Optional; nil
	// (or an empty peerNamespaces) means peers are not propagated to.
	sessionsByUser func(ctx context.Context, namespace string, userID int64) ([]*session.Session, error)
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

// clearPeers takes the same flag off this user's sessions in the peer
// namespaces, so a debt settled on one surface releases the others.
//
// Best-effort on purpose, and safe to be: a peer whose flag survives stays
// blocked exactly as it is today — the protocol resolver keeps reporting it as
// no session and the user authenticates once more at the next RP hop. The
// failure mode is a lost convenience, never a reopened gate, so it must not
// refuse the request that settled the debt.
//
// Scoped to userID by construction: sessionsByUser reads the per-user index,
// so no other account's sessions are reachable from here.
func (g obligationGate) clearPeers(ctx context.Context, userID int64) {
	if g.sessionsByUser == nil || userID == 0 {
		return
	}
	for _, ns := range g.peerNamespaces {
		if ns == g.namespace {
			continue // already cleared as the request's own session
		}
		sessions, err := g.sessionsByUser(ctx, ns, userID)
		if err != nil {
			continue
		}
		for _, sess := range sessions {
			if sess == nil {
				continue
			}
			_ = g.clearFlag(ctx, ns, sess.ID, false)
		}
	}
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
			userID := c.GetInt64(CtxUserID)
			if owes, err := g.stillOwes(c.Request.Context(), userID); err == nil && !owes {
				// Only now — with the debt confirmed settled against durable
				// state, not merely claimed — may the flag come off. Clearing
				// it is a relaxation, so it never runs ahead of that check.
				//
				// Fail closed if the write-back does not land: letting the
				// request through on an unwritten promise would hold the gate
				// open for a session that still reads as pending. The
				// remediation allowance below stays reachable, so this cannot
				// deadlock, and the next request retries the write.
				if err := g.clearFlag(c.Request.Context(), g.namespace, c.GetString(CtxSessionID), false); err == nil {
					g.clearPeers(c.Request.Context(), userID)
					c.Next()
					return
				}
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

package authn

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/session"
)

// OptionalAuthMiddleware resolves the session cookie when one is present and
// valid, and does nothing when it is not. It never rejects.
//
// This exists for the external-IdP callback, which serves two flows through
// one URL: an anonymous visitor signing in, and a signed-in user attaching an
// external account to their profile. The second needs to know who is calling;
// the first must not be blocked. Mount it on that single route, never on a
// whole group — the surrounding portal-public group also carries login-start
// routes where injecting a session is meaningless.
//
// On a valid session it stamps both the gin context (CtxUserID and friends,
// same keys AuthMiddleware sets) and the auditctx actor on the request
// context. The second is not decorative: the external-IdP feature lives in
// the separate mxid-ee module and cannot import this internal package, so it
// reads the caller back via auditctx.From instead of authn.CtxUserID — the
// same pattern the form-fill feature already uses.
//
// Deliberately does NOT call sessionMgr.Touch. AuthMiddleware touches to
// extend the idle window on real user activity, and its own comment warns
// that touching from the wrong place keeps idle sessions alive forever. A
// visit to the OAuth callback is not user activity in that sense — an
// anonymous login through this same route touches nothing either, and
// treating the authenticated case differently would make an idle session's
// lifetime depend on whether the user happened to have a stale cookie set
// while starting an unrelated bind flow.
func OptionalAuthMiddleware(sessionMgr *session.Manager, namespace string) gin.HandlerFunc {
	cookieName := cookieForNamespace(namespace)

	return func(c *gin.Context) {
		if cookieName == "" {
			c.Next()
			return
		}
		sessionID, err := c.Cookie(cookieName)
		if err != nil || sessionID == "" {
			c.Next()
			return
		}
		sess, err := sessionMgr.Get(c.Request.Context(), namespace, sessionID)
		if err != nil || sess == nil {
			c.Next()
			return
		}

		c.Set(CtxUserID, sess.UserID)
		c.Set(CtxTenantID, sess.TenantID)
		c.Set(CtxSessionID, sess.ID)
		c.Set(CtxNamespace, namespace)

		ctx := auditctx.With(c.Request.Context(), auditctx.Actor{
			ActorID:   sess.UserID,
			ActorType: actorTypeForNamespace(namespace),
			TenantID:  sess.TenantID,
			SessionID: sess.ID,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

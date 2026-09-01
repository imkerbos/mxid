package oidcop

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/ssoflow"
)

// AccessChecker reports whether a user is allowed to access an app under the
// app's access policy (group/org/role bindings, deny rules). Mirrors the
// hand-rolled engine's CheckAppAccess enforcement
// (internal/protocol/oidc/handler.go:373-386); reason is a machine token
// (e.g. "no-rule-matched", "deny:user:42") surfaced to the portal "no access"
// page.
type AccessChecker interface {
	CheckAppAccess(ctx context.Context, userID, appID, tenantID int64) (allowed bool, reason string, err error)
}

// ParticipationTracker records that an OIDC app authenticated a user within a
// protocol SSO session, feeding the WS2 back-channel logout fan-out index
// (internal/protocol/oidclogout.Index). ttl mirrors the session's remaining
// absolute window so the tracking set self-cleans with it.
type ParticipationTracker interface {
	Track(ctx context.Context, sid string, appID int64, ttl time.Duration) error
}

// LoginBridge connects op's AuthRequest lifecycle to MXID's BFF portal login +
// consent. op redirects an unauthenticated user to loginURL(authRequestID),
// which points at Handle below; once the user has a session (and consent),
// Handle marks the request done and bounces to op's callback to issue the code.
//
// Reuses the portal SPA's existing `return_to` convention for both login and
// consent, so NO portal frontend change is required.
type LoginBridge struct {
	storage       *Storage
	apps          resolver.AppResolver
	sessions      resolver.SessionResolver
	confirm       *ssoflow.ConfirmStore
	access        AccessChecker
	participation ParticipationTracker
	callbackURL   func(context.Context, string) string
	loginURL      func(authRequestID string) string
	portalURL     string
	// authorizer is the op provider, used only to answer a declined consent
	// with a spec-shaped error response. May be nil, which degrades that one
	// case to a plain redirect back to the portal.
	authorizer op.Authorizer
}

// NewLoginBridge wires a LoginBridge. loginURL must build the external URL of
// Handle for a given authRequestID (same builder op uses as the client LoginURL),
// since it doubles as the post-login/consent return_to target. access may be
// nil, which skips the app access policy check entirely (matches the
// hand-rolled engine's `if h.access != nil` guard). participation may be nil,
// which skips WS2 back-channel-logout tracking entirely. confirm may be nil,
// which skips the SSO login-confirmation gate entirely (matches the hand-rolled
// engine's `if h.confirm != nil` guard).
func NewLoginBridge(
	storage *Storage,
	apps resolver.AppResolver,
	sessions resolver.SessionResolver,
	confirm *ssoflow.ConfirmStore,
	access AccessChecker,
	participation ParticipationTracker,
	callbackURL func(context.Context, string) string,
	loginURL func(string) string,
	portalURL string,
	authorizer op.Authorizer,
) *LoginBridge {
	return &LoginBridge{
		storage:       storage,
		apps:          apps,
		sessions:      sessions,
		confirm:       confirm,
		access:        access,
		participation: participation,
		callbackURL:   callbackURL,
		loginURL:      loginURL,
		portalURL:     portalURL,
		authorizer:    authorizer,
	}
}

// Handle is the GET endpoint op redirects to: /protocol/oidc/login?authRequestID=…
func (b *LoginBridge) Handle(c *gin.Context) {
	authReqID := c.Query("authRequestID")
	if authReqID == "" {
		authReqID = c.Query("id")
	}
	if authReqID == "" {
		c.String(http.StatusBadRequest, "missing authRequestID")
		return
	}

	ctx := c.Request.Context()
	ar, err := b.storage.AuthRequestByID(ctx, authReqID)
	if err != nil {
		c.String(http.StatusBadRequest, "unknown or expired auth request")
		return
	}

	// Resolve the SSO session from the protocol cookie, falling back to the
	// portal cookie (IdP-initiated / already-logged-in portal users). protoSID
	// is non-empty ONLY when a genuine protocol-namespace session backed the
	// login — never for the portal fallback — so the id_token `sid` we emit
	// downstream can never leak a portal session id.
	sess, protoSID := b.resolveSession(ctx, c)
	if sess == nil {
		// Not logged in → portal login, returning here afterwards.
		b.redirect(c, b.portalURL+"/login?return_to="+url.QueryEscape(b.loginURL(authReqID)))
		return
	}

	app, err := b.apps.GetAppByClientID(ctx, ar.GetClientID())
	if err != nil || app == nil {
		c.String(http.StatusBadRequest, "unknown client")
		return
	}

	// App access policy check (internal/domain/appaccess), ported from the
	// hand-rolled engine (internal/protocol/oidc/handler.go:373-386). Runs
	// BEFORE consent — no point asking for scope consent if the user can't
	// access the app at all — and before the auth request is ever marked
	// done, so a denied user gets no code/tokens. Fail-closed: an adapter
	// error denies (mirrors the hand-rolled engine's redirectError on
	// CheckAppAccess error, not a fail-open default).
	if b.access != nil {
		allowed, reason, err := b.access.CheckAppAccess(ctx, sess.UserID, app.ID, sess.TenantID)
		if err != nil {
			c.String(http.StatusInternalServerError, "access policy check failed")
			return
		}
		if !allowed {
			// Portal "no access" page, not an OIDC error redirect to the RP's
			// redirect_uri — same UX call the hand-rolled engine makes so the
			// user gets a friendly explanation instead of a JSON 403 bounced
			// through the SP.
			b.redirect(c, b.portalURL+"/no-access?app="+app.Code+"&reason="+reason)
			return
		}
	}

	// SSO login confirmation (Google-style product requirement), ported from the
	// hand-rolled engine (internal/protocol/oidc/handler.go:388-409).
	//   IdP-initiated (portal app-list launch, idp_initiated=1) → SEAMLESS: no
	//     confirm screen, no token — the user chose this app in our own UI.
	//   SP-initiated (a third-party app redirected the user here) → require a
	//     one-time sso_confirm token EVERY login. The portal confirm page's
	//     approve mints it (and records the scope grant); this endpoint consumes
	//     it exactly once. Missing / invalid / already-consumed → bounce to the
	//     portal confirm page (return_to = this same bridge endpoint), which
	//     mints a fresh token and replays back here. Persisted consent is
	//     deliberately NOT consulted as a shortcut: matching the hand-rolled
	//     engine, an SP-initiated login to an already-consented app still
	//     confirms.
	// prompt=none never reaches here — Storage.CreateAuthRequest rejects it
	// upfront with login_required (storage.go), so there is no
	// interaction_required branch to mirror at this point.
	idpInitiated := false
	if a, ok := ar.(*authRequest); ok {
		idpInitiated = a.IdpInitiated
	}
	if !idpInitiated && b.confirm != nil {
		// sso_deny=1 → the user pressed Cancel on the confirm page.
		//
		// This branch was missing, and its absence did not fail — it looped.
		// Cancel sends the browser back to this endpoint with sso_deny=1, which
		// nothing here read, so the request fell through to the token check,
		// found no token, and bounced to the confirm page again. Pressing
		// Cancel redisplayed the page it was cancelling, with no way out but
		// the back button. CAS and SAML both handled it; only OIDC did not.
		//
		// The answer owed to the RP is access_denied at its redirect_uri
		// (OIDC Core 3.1.2.6), not a page on our side: the application asked a
		// question and is entitled to hear that the user said no, so it can
		// show its own sign-in again rather than hang on a callback that never
		// arrives.
		if c.Query("sso_deny") == "1" {
			b.denyAuthRequest(c, ctx, authReqID, ar)
			return
		}
		if !b.confirm.Consume(ctx, c.Query("sso_confirm"), sess.UserID, app.ID) {
			scope := joinScopes(ar.GetScopes())
			b.redirect(c, b.portalURL+"/consent?app_id="+itoa(app.ID)+
				"&scope="+url.QueryEscape(scope)+
				"&return_to="+url.QueryEscape(b.loginURL(authReqID)))
			return
		}
	}

	// Record (sid, appID) participation for WS2 back-channel logout fan-out —
	// only when a genuine protocol-namespace session backs this login.
	// Passwordless logins (magic-link / SMS-OTP) mint no protocol session, so
	// protoSID is empty and correctly skip tracking (no sid to correlate a
	// downstream logout_token to). ttl mirrors the session's remaining
	// absolute window so the tracking set self-cleans with it.
	if b.participation != nil && protoSID != "" {
		_ = b.participation.Track(ctx, protoSID, app.ID, time.Until(sess.ExpiresAt))
	}

	// Authenticated + consented → mark done and hand back to op for the code.
	amr := []string{"pwd"}
	if sess.AuthType == "mfa" {
		amr = append(amr, "mfa")
	}
	if err := b.storage.AuthRequestDone(ctx, authReqID, itoa(sess.UserID), time.Now(), amr, protoSID); err != nil {
		c.String(http.StatusBadRequest, "unknown or expired auth request")
		return
	}
	b.redirect(c, b.callbackURL(ctx, authReqID))
}

// denyAuthRequest answers a declined consent the way the protocol expects: an
// access_denied error delivered to the client's registered redirect_uri, with
// the original state so the RP can match it to the request it started.
//
// op.AuthRequestError builds that response from the STORED auth request, so the
// redirect_uri is the one already validated against the client's registration —
// never a value echoed back from this request's query string, which is what
// would make this an open redirect.
//
// The auth request is deleted first: it has been answered, and leaving it live
// would let a replay of the same URL resume a flow the user rejected.
func (b *LoginBridge) denyAuthRequest(c *gin.Context, ctx context.Context, authReqID string, ar op.AuthRequest) {
	if b.storage != nil {
		_ = b.storage.DeleteAuthRequest(ctx, authReqID)
	}
	// No authorizer wired (or no redirect_uri to answer to): fall back to the
	// portal, so Cancel still leaves the confirm page instead of looping.
	if b.authorizer == nil || ar == nil || ar.GetRedirectURI() == "" {
		b.redirect(c, b.portalURL+"/")
		return
	}
	op.AuthRequestError(c.Writer, c.Request, ar,
		oidc.ErrAccessDenied().WithDescription("user denied the login confirmation"),
		b.authorizer)
	c.Abort()
}

// resolveSession finds the logged-in SSO session for this request and reports
// the protocol-namespace session id backing it (empty when none).
//
// The protocol cookie is authoritative: when it resolves to a live
// NamespaceProtocol session (verified via GetProtocolSSOSession — no portal
// fallback), that id is returned as protoSID and becomes the id_token `sid`.
// The portal cookie is only a login fallback (IdP-initiated / SPA-logged-in
// users, and passwordless flows — magic-link / SMS-OTP — that create ONLY a
// portal session): it proves the user is authenticated so login can complete,
// but it is NOT a protocol session, so protoSID stays empty and no `sid` is
// emitted. WS2 back-channel logout keys strictly on the protocol namespace, so
// emitting a portal id there would be a silent correlation failure.
func (b *LoginBridge) resolveSession(ctx context.Context, c *gin.Context) (sess *resolver.SSOSession, protoSID string) {
	if sid, err := c.Cookie("mxid_proto_sid"); err == nil && sid != "" {
		if s, err := b.sessions.GetProtocolSSOSession(ctx, sid); err == nil && s != nil {
			return s, sid
		}
	}
	if sid, err := c.Cookie("mxid_portal_sid"); err == nil && sid != "" {
		if s, err := b.sessions.GetSSOSession(ctx, sid); err == nil && s != nil {
			return s, ""
		}
	}
	return nil, ""
}

func (b *LoginBridge) redirect(c *gin.Context, to string) {
	c.Redirect(http.StatusFound, to)
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }
func itoa(i int64) string               { return strconv.FormatInt(i, 10) }

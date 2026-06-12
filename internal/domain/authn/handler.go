package authn

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
)

// Cookie names per namespace.
//
// The protocol cookie is shared by all SSO protocol handlers (OIDC/SAML/CAS)
// and is decoupled from the SPA session cookies: SPA logout MUST NOT remove
// the protocol session (OIDC spec §10 — RP-initiated logout is the only way
// to terminate SSO). The protocol cookie is set on successful login alongside
// the SPA cookie and removed only by the OIDC end_session_endpoint.
const (
	CookieConsole = "mxid_console_sid"
	CookiePortal  = "mxid_portal_sid"
	CookieProto   = "mxid_proto_sid"
)

// LoginRequest is the API request for logging in.
//
// Remember=true upgrades the response cookies to persistent (explicit MaxAge
// = 30 days) so the user stays logged in across browser restarts. Default
// (false) leaves cookies as session cookies that vanish on browser close.
type LoginRequest struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	AuthType    string `json:"auth_type"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
	Remember    bool   `json:"remember"`
	// Tenant is the tenant code (e.g. "matrixplus") the portal user is
	// signing into. Optional — when empty falls back to the handler's
	// default tenant. Used by the multi-tenant portal where the same
	// MXID instance hosts multiple independent enterprises.
	Tenant string `json:"tenant"`
}

// rememberMeMaxAge is how long persistent session cookies survive when the
// caller opted into Remember Me. Matches the Auth0 / Okta 30-day default.
const rememberMeMaxAge = 30 * 24 * 60 * 60

// CurrentUserResponse is returned by the /auth/me endpoint.
type CurrentUserResponse struct {
	UserID      int64  `json:"user_id,string"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      int    `json:"status"`
	// IsAdmin reports whether the user has any non-empty admin permission
	// — i.e. would the console route guard let them in. The portal SPA
	// uses this to decide whether to show the "switch to console" button.
	IsAdmin bool `json:"is_admin"`
}

// AdminChecker tells whether the given user holds enough permission to
// see the admin console. nil = assume false (legacy behaviour, no
// switch-to-console button rendered).
type AdminChecker func(ctx context.Context, tenantID, userID int64) bool

// TenantCodeResolver maps a tenant code (e.g. "matrixplus") to an int64 id.
// Returns 0 when not found.
type TenantCodeResolver func(ctx context.Context, code string) int64

// Handler serves authentication HTTP endpoints.
// LoginMethodGate returns an error when the requested auth_type is disabled
// by the admin. Implementations live in cmd/server/main.go and consult the
// settings DB. nil = no gating (legacy behaviour, password always allowed).
type LoginMethodGate func(ctx context.Context, authType string) error

// RememberMeProvider returns the configured remember-me cookie TTL in
// seconds. nil = legacy hardcoded 30-day default.
type RememberMeProvider func(ctx context.Context) int

type Handler struct {
	engine       *Engine
	captchaSvc   *CaptchaService
	tenantID     int64
	tenantByCode TenantCodeResolver
	cookieSecure bool
	cookieDomain string
	methodGate   LoginMethodGate
	rememberMe   RememberMeProvider
	adminCheck   AdminChecker
}

// SetAdminChecker wires the runtime "is this user a console-eligible
// admin?" lookup used by /auth/me to flag the switch-to-console button.
func (h *Handler) SetAdminChecker(c AdminChecker) { h.adminCheck = c }

// SetLoginMethodGate wires the runtime "is this method enabled?" check
// that loginHandler runs before consuming password / captcha state.
func (h *Handler) SetLoginMethodGate(g LoginMethodGate) { h.methodGate = g }

// SetRememberMeProvider wires the runtime cookie TTL lookup for the
// "remember me" branch. Provider returns seconds; non-positive falls back
// to the static rememberMeMaxAge.
func (h *Handler) SetRememberMeProvider(p RememberMeProvider) { h.rememberMe = p }

// NewHandler creates a new auth handler.
func NewHandler(engine *Engine, captchaSvc *CaptchaService, tenantID int64, cookieSecure bool, cookieDomain string) *Handler {
	return &Handler{
		engine:       engine,
		captchaSvc:   captchaSvc,
		tenantID:     tenantID,
		cookieSecure: cookieSecure,
		cookieDomain: cookieDomain,
	}
}

// SetTenantResolver wires the multi-tenant lookup used by the LoginRequest.Tenant
// field. When nil the handler always falls back to the default tenant_id.
func (h *Handler) SetTenantResolver(r TenantCodeResolver) { h.tenantByCode = r }

// RegisterConsoleRoutes registers auth routes on the console API group.
func (h *Handler) RegisterConsoleRoutes(rg *gin.RouterGroup) {
	auth := rg.Group("/auth")
	{
		auth.GET("/captcha", h.captchaHandler())
		auth.POST("/login", h.loginHandler(session.NamespaceConsole, CookieConsole))
		auth.POST("/mfa/verify", h.verifyMFAHandler(session.NamespaceConsole, CookieConsole))
		auth.POST("/logout", h.logoutHandler(session.NamespaceConsole, CookieConsole))
		auth.GET("/me", h.meHandler(session.NamespaceConsole, CookieConsole))
		// Seamless SSO: derive a console session from the user's active portal
		// session (preferred — stays warm) or the shared proto SSO session.
		// Admin-gated — non-admins get 403 and fall back to login.
		auth.POST("/sso", h.ssoHandler(session.NamespaceConsole, CookieConsole, true, []ssoSource{
			{session.NamespacePortal, CookiePortal},
			{session.NamespaceProtocol, CookieProto},
		}))
		// Step-up: re-verify MFA on the current console session to clear a
		// high-risk operation's step_up_required gate.
		auth.POST("/step-up", h.stepUpHandler())
	}
}

// RegisterPortalRoutes registers auth routes on the portal API group.
func (h *Handler) RegisterPortalRoutes(rg *gin.RouterGroup) {
	auth := rg.Group("/auth")
	{
		auth.GET("/captcha", h.captchaHandler())
		auth.POST("/login", h.loginHandler(session.NamespacePortal, CookiePortal))
		auth.POST("/mfa/verify", h.verifyMFAHandler(session.NamespacePortal, CookiePortal))
		auth.POST("/logout", h.logoutHandler(session.NamespacePortal, CookiePortal))
		auth.GET("/me", h.meHandler(session.NamespacePortal, CookiePortal))
		// Seamless SSO: derive a portal session from the user's active console
		// session (e.g. switching back from console) or the shared proto SSO
		// session. Open to any authenticated identity.
		auth.POST("/sso", h.ssoHandler(session.NamespacePortal, CookiePortal, false, []ssoSource{
			{session.NamespaceConsole, CookieConsole},
			{session.NamespaceProtocol, CookieProto},
		}))
	}
}

// captchaHandler returns a gin.HandlerFunc that generates a new captcha.
func (h *Handler) captchaHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		captcha, err := h.captchaSvc.Generate()
		if err != nil {
			response.InternalError(c, "failed to generate captcha")
			return
		}
		response.OK(c, captcha)
	}
}

// loginHandler returns a gin.HandlerFunc for the given namespace and cookie name.
func (h *Handler) loginHandler(namespace, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			response.BadRequest(c, 40001, err.Error())
			return
		}

		// Validate captcha
		if req.CaptchaID == "" || req.CaptchaCode == "" {
			response.BadRequest(c, 40003, "captcha is required")
			return
		}
		if !h.captchaSvc.Verify(req.CaptchaID, req.CaptchaCode) {
			response.BadRequest(c, 40004, "invalid captcha")
			return
		}

		authType := req.AuthType
		if authType == "" {
			authType = "local"
		}

		// Login-method gate: admin can disable password / sms / magic-link
		// via the settings UI. We bounce here BEFORE consuming any captcha
		// quota so the user can retry on a different method without re-
		// fetching captcha. Implementations may be nil during early boot
		// or tests.
		if h.methodGate != nil {
			if err := h.methodGate(c.Request.Context(), authType); err != nil {
				response.BadRequest(c, 40005, err.Error())
				return
			}
		}

		// Resolve target tenant for this login attempt. Portal `?tenant=<code>`
		// becomes req.Tenant — when set we look it up via tenantByCode; the
		// fallback is the handler's default tenant (single-tenant deployments).
		effectiveTenant := h.tenantID
		if req.Tenant != "" && h.tenantByCode != nil {
			if tid := h.tenantByCode(c.Request.Context(), req.Tenant); tid > 0 {
				effectiveTenant = tid
			}
		}
		authReq := &AuthRequest{
			TenantID: effectiveTenant,
			AuthType: authType,
			Credentials: map[string]string{
				"username": req.Username,
				"password": req.Password,
			},
			ClientIP:  c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		}

		loginResp, err := h.engine.Login(c.Request.Context(), authReq, namespace)
		if err != nil {
			h.handleAuthError(c, err)
			return
		}

		// Password OK but second factor required — no cookies yet. Client
		// holds the challenge token and posts it back to /auth/mfa/verify
		// together with the TOTP code. The Remember flag is NOT carried
		// across the MFA step (challenge payload is intentionally minimal);
		// re-send it on the verify call.
		if loginResp.MFARequired {
			response.OK(c, loginResp)
			return
		}

		h.finalizeLoginCookies(c, cookieName, loginResp, authType, req.Remember)
		response.OK(c, loginResp)
	}
}

// VerifyMFARequest is the request body for the MFA challenge step.
//
// Challenge is the opaque token returned by /auth/login when mfa_required=true.
// Code is the 6-digit TOTP value from the user's authenticator app. Remember
// re-applies the persistent-cookie upgrade that /auth/login carried — it is
// intentionally NOT stored in the challenge payload (single source of truth =
// the client's intent at the moment they finish the login flow).
type VerifyMFARequest struct {
	Challenge string `json:"challenge" binding:"required"`
	Code      string `json:"code" binding:"required"`
	Remember  bool   `json:"remember"`
}

// verifyMFAHandler completes a login deferred by the MFA gate. Same response
// shape as /auth/login success — sets the SPA + proto cookies and returns
// the user info. On invalid code the challenge is already consumed; client
// must restart the password login.
func (h *Handler) verifyMFAHandler(namespace, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req VerifyMFARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			response.BadRequest(c, 40001, err.Error())
			return
		}

		loginResp, err := h.engine.VerifyMFAChallenge(c.Request.Context(), req.Challenge, req.Code)
		if err != nil {
			h.handleAuthError(c, err)
			return
		}

		h.finalizeLoginCookies(c, cookieName, loginResp, "totp", req.Remember)
		// The user just passed MFA at login — stamp the SPA session so an
		// immediate high-risk operation falls inside the step-up grace window.
		_ = h.engine.SessionManager().MarkMFAVerified(c.Request.Context(), namespace, loginResp.SessionID)
		response.OK(c, loginResp)
	}
}

// finalizeLoginCookies sets the SPA + protocol session cookies for a fully
// authenticated login response (first-factor success or post-MFA success).
// Splitting this out lets /auth/login and /auth/mfa/verify share identical
// cookie semantics — including the "proto-session bridge failure is non-fatal"
// rule below.
func (h *Handler) finalizeLoginCookies(c *gin.Context, cookieName string, loginResp *LoginResponse, authType string, remember bool) {
	// Set SPA-scope session cookie (portal / console). Remember Me upgrades
	// to a persistent cookie instead of a session cookie.
	h.setSessionCookieWithRemember(c, cookieName, loginResp.SessionID, remember)

	// Bridge to protocol-scope SSO session. Failure here MUST NOT block the
	// SPA login — the user is still authenticated for the SPA; they just
	// lose SSO short-circuit and will have to re-auth at /protocol/oidc/authorize
	// the next time an RP redirects.
	if protoSess, err := h.engine.SessionManager().Create(
		c.Request.Context(),
		session.NamespaceProtocol,
		loginResp.UserID,
		h.tenantID,
		c.ClientIP(),
		c.Request.UserAgent(),
		authType,
	); err == nil {
		h.setProtoSessionCookieWithRemember(c, protoSess.ID, remember)
	}
}

// logoutHandler returns a gin.HandlerFunc for the given namespace and cookie name.
func (h *Handler) logoutHandler(namespace, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie(cookieName)
		if err != nil || sessionID == "" {
			response.Unauthorized(c, 40101, "not authenticated")
			return
		}

		// Get session to find user ID
		sess, sErr := h.engine.GetSession(c.Request.Context(), namespace, sessionID)
		var userID int64
		if sErr == nil && sess != nil {
			userID = sess.UserID
		}

		if err := h.engine.Logout(c.Request.Context(), namespace, sessionID, userID); err != nil {
			response.InternalError(c, "logout failed")
			return
		}

		// Clear cookie
		h.clearSessionCookie(c, cookieName)

		response.OK(c, nil)
	}
}

// meHandler returns a gin.HandlerFunc for the current-user endpoint.
func (h *Handler) meHandler(namespace, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie(cookieName)
		if err != nil || sessionID == "" {
			response.Unauthorized(c, 40101, "not authenticated")
			return
		}

		sess, err := h.engine.GetSession(c.Request.Context(), namespace, sessionID)
		if err != nil {
			response.Unauthorized(c, 40101, "invalid session")
			return
		}

		userInfo, err := h.engine.GetCurrentUser(c.Request.Context(), sess.UserID)
		if err != nil {
			response.InternalError(c, "failed to get user info")
			return
		}

		isAdmin := false
		if h.adminCheck != nil {
			isAdmin = h.adminCheck(c.Request.Context(), sess.TenantID, sess.UserID)
		}
		response.OK(c, &CurrentUserResponse{
			UserID:      userInfo.ID,
			Username:    userInfo.Username,
			DisplayName: userInfo.DisplayName,
			Status:      userInfo.Status,
			IsAdmin:     isAdmin,
		})
	}
}

// ssoSource is a place to look for an existing valid session to derive a new
// SPA session from — a (namespace, cookie) pair.
type ssoSource struct {
	namespace string
	cookie    string
}

// ssoHandler bridges an existing session into a fresh SPA session for the
// target namespace WITHOUT re-entering credentials — the mechanism behind
// seamless portal⇄console switching.
//
// It tries each source in order and uses the first VALID session as the
// identity. Sources list the SIBLING SPA session first (portal for a console
// bridge, console for a portal bridge), then the shared proto/SSO session.
//
// Why sibling-first: the proto session idle-expires independently (nothing
// Touch()es it after login), while the SPA the user is actively viewing keeps
// its session warm. Deriving from the sibling makes the switch survive a
// proto session that idle-died under an otherwise-active login — the exact
// failure seen in the wild (portal polling kept mxid_portal_sid alive; the
// untouched mxid_proto_sid expired at 30m → bridge 401 → spurious re-login).
//
// requireAdmin gates the console target — only AdminChecker-approved users get
// a console session; others get 403 and the SPA falls back to the login form.
// The minted session is non-persistent and carries its own idle/absolute
// lifetime. AuthType is carried forward, preserving the step-up hook.
func (h *Handler) ssoHandler(targetNS, targetCookie string, requireAdmin bool, sources []ssoSource) gin.HandlerFunc {
	return func(c *gin.Context) {
		var src *session.Session
		for _, s := range sources {
			id, err := c.Cookie(s.cookie)
			if err != nil || id == "" {
				continue
			}
			if sess, err := h.engine.GetSession(c.Request.Context(), s.namespace, id); err == nil && sess != nil {
				src = sess
				break
			}
		}
		if src == nil {
			response.Unauthorized(c, 40101, "no valid session to bridge")
			return
		}

		if requireAdmin {
			if h.adminCheck == nil || !h.adminCheck(c.Request.Context(), src.TenantID, src.UserID) {
				response.Forbidden(c, 40301, "not authorized for console")
				return
			}
		}

		spaSess, err := h.engine.SessionManager().Create(
			c.Request.Context(),
			targetNS,
			src.UserID,
			src.TenantID,
			c.ClientIP(),
			c.Request.UserAgent(),
			src.AuthType,
		)
		if err != nil {
			response.InternalError(c, "failed to establish session")
			return
		}

		h.setSessionCookieWithRemember(c, targetCookie, spaSess.ID, false)
		response.OK(c, nil)
	}
}

// StepUpRequest carries the MFA code submitted for a step-up challenge.
type StepUpRequest struct {
	Code string `json:"code" binding:"required"`
}

// stepUpHandler re-verifies the user's MFA on their existing console session
// and refreshes MFAVerifiedAt, so subsequent high-risk operations fall inside
// the grace window without another prompt. The user must already hold a valid
// console session (the SPA calls this after a high-risk op returns
// step_up_required). Reuses the same MFA verifier and rate limiter as login.
func (h *Handler) stepUpHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, err := c.Cookie(CookieConsole)
		if err != nil || sid == "" {
			response.Unauthorized(c, 40101, "authentication required")
			return
		}
		sess, err := h.engine.GetSession(c.Request.Context(), session.NamespaceConsole, sid)
		if err != nil {
			response.Unauthorized(c, 40101, "invalid or expired session")
			return
		}

		var req StepUpRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			response.BadRequest(c, 40001, err.Error())
			return
		}

		if err := h.engine.VerifyStepUp(c.Request.Context(), sess.UserID, c.ClientIP(), req.Code); err != nil {
			h.handleAuthError(c, err)
			return
		}

		if err := h.engine.SessionManager().MarkMFAVerified(c.Request.Context(), session.NamespaceConsole, sid); err != nil {
			response.InternalError(c, "failed to record mfa verification")
			return
		}
		response.OK(c, nil)
	}
}

// setSessionCookieWithRemember writes the SPA session cookie, switching to
// a 30-day persistent cookie when the user opted into Remember Me.
// Browser-session cookie (no MaxAge) is the default — vanishes on close.
//
// SameSite=Lax is the CSRF baseline: top-level GET navigations still carry
// the cookie (so SSO bounces work) but cross-site form POSTs / fetches do
// not. Combined with the CSRF middleware's Origin check this is defense in
// depth against the classic forged-form attack.
func (h *Handler) setSessionCookieWithRemember(c *gin.Context, name, value string, remember bool) {
	maxAge := 86400 // 24h default for active session
	if remember {
		maxAge = h.rememberMaxAge(c.Request.Context())
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, maxAge, "/", h.cookieDomain, h.cookieSecure, true)
}

// setProtoSessionCookieWithRemember writes the protocol-scope cookie with
// extended TTL when remember=true. Mirrors the SPA cookie's persistence so
// SSO continues to short-circuit re-auth across browser restarts for users
// who opted in.
//
// Stays SameSite=Lax: the proto cookie is read inside top-level redirects
// from RPs to /protocol/oidc/authorize and /protocol/saml/sso (GET / 302
// flow). Strict would break SSO when the user clicks an RP link.
func (h *Handler) setProtoSessionCookieWithRemember(c *gin.Context, value string, remember bool) {
	maxAge := 24 * 60 * 60
	if remember {
		maxAge = h.rememberMaxAge(c.Request.Context())
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(CookieProto, value, maxAge, "/", h.cookieDomain, h.cookieSecure, true)
}

// rememberMaxAge returns the runtime-configured remember-me cookie TTL in
// seconds. Falls back to the static rememberMeMaxAge constant when no
// provider is wired or the provider returns a non-positive value.
func (h *Handler) rememberMaxAge(ctx context.Context) int {
	if h.rememberMe != nil {
		if v := h.rememberMe(ctx); v > 0 {
			return v
		}
	}
	return rememberMeMaxAge
}

// clearSessionCookie removes the session cookie.
//
// SameSite attribute must match the original Set-Cookie for browsers to
// reliably target the same cookie for deletion.
func (h *Handler) clearSessionCookie(c *gin.Context, name string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, "", -1, "/", h.cookieDomain, h.cookieSecure, true)
}

// handleAuthError maps engine errors to HTTP responses.
func (h *Handler) handleAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrAuthFailed):
		response.Unauthorized(c, 40101, "invalid credentials")
	case errors.Is(err, ErrAccountLocked):
		response.Error(c, http.StatusForbidden, 40301, "account is locked", "")
	case errors.Is(err, ErrPasswordExpired):
		response.Error(c, http.StatusForbidden, 40302, "password has expired", "")
	case errors.Is(err, ErrMFARequired):
		response.OK(c, map[string]any{
			"mfa_required": true,
		})
	case errors.Is(err, ErrMFAChallengeNotFound):
		response.BadRequest(c, 40004, "mfa challenge expired, please log in again")
	case errors.Is(err, ErrMFAVerifyFailed):
		response.Unauthorized(c, 40102, "invalid mfa code")
	case errors.Is(err, ErrMFARateLimited):
		// Surface Retry-After so SPAs can show a countdown.
		var rle *MFARateLimitError
		if errors.As(err, &rle) {
			c.Header("Retry-After", strconv.Itoa(int(rle.RetryAfter.Seconds())))
		}
		response.Error(c, http.StatusTooManyRequests, 42901, "mfa rate limited", err.Error())
	case errors.Is(err, ErrMFANotConfigured):
		response.InternalError(c, "mfa not configured")
	case errors.Is(err, ErrUnknownProvider):
		response.BadRequest(c, 40002, "unsupported auth type")
	default:
		response.InternalError(c, "authentication error")
	}
}

// Context keys used by the auth middleware to pass values via gin.Context.
const (
	CtxUserID    = "user_id"
	CtxTenantID  = "tenant_id"
	CtxSessionID = "session_id"
)

// GetUserID extracts the authenticated user ID from the gin context.
func GetUserID(c *gin.Context) (int64, bool) {
	v, exists := c.Get(CtxUserID)
	if !exists {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

// GetTenantID extracts the tenant ID from the gin context.
func GetTenantID(c *gin.Context) (int64, bool) {
	v, exists := c.Get(CtxTenantID)
	if !exists {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

// GetSessionID extracts the session ID from the gin context.
func GetSessionID(c *gin.Context) (string, bool) {
	v, exists := c.Get(CtxSessionID)
	if !exists {
		return "", false
	}
	id, ok := v.(string)
	return id, ok
}

// UserIDStr returns the user ID as a string for convenience.
func UserIDStr(c *gin.Context) string {
	id, ok := GetUserID(c)
	if !ok {
		return ""
	}
	return strconv.FormatInt(id, 10)
}

package externalidp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
)

// ConsoleGate authorizes a resolved external identity for console access.
// Returns nil to allow; a non-nil error's message becomes the login-page
// failure reason. It must reject (a) users without admin authorization and
// (b) is_builtin break-glass accounts (which are local-login only).
type ConsoleGate func(ctx context.Context, tenantID, userID int64) error

// ConsoleHandler drives external-IdP login for the admin console. It mirrors
// PortalHandler's OAuth dance but differs in three security-critical ways:
//
//   - auto-create is FORCED off: a console login only succeeds for a user who
//     already has a binding AND was provisioned through the portal/admin flow.
//   - a ConsoleGate runs after identity resolution: only admin-authorized,
//     non-built-in users get a session.
//   - it mints a console session (mxid_console_sid), not a portal/proto one.
type ConsoleHandler struct {
	svc          *Service
	resolver     IdentityResolver
	sessionMgr   *session.Manager
	gate         ConsoleGate
	tenantID     int64
	tenantByCode TenantCodeResolver
	baseURL      string
	consoleURL   string
	loginURL     string
	failureURL   string
	cookieName   string
	cookieDomain string
	cookieSecure bool
}

// ConsoleHandlerOpts groups constructor parameters.
type ConsoleHandlerOpts struct {
	Svc          *Service
	Resolver     IdentityResolver
	SessionMgr   *session.Manager
	Gate         ConsoleGate
	TenantID     int64
	TenantByCode TenantCodeResolver
	BaseURL      string // backend reachable URL, used for callback URI
	ConsoleURL   string // frontend console reachable URL, used for post-login redirect
	LoginURL     string // path under ConsoleURL, e.g. /admin/
	FailureURL   string // path under ConsoleURL, e.g. /admin/login?err=external
	CookieName   string
	CookieDomain string
	CookieSecure bool
}

func NewConsoleHandler(opts ConsoleHandlerOpts) *ConsoleHandler {
	consoleURL := opts.ConsoleURL
	if consoleURL == "" {
		consoleURL = opts.BaseURL
	}
	loginPath := opts.LoginURL
	if loginPath == "" {
		loginPath = "/admin/"
	}
	failurePath := opts.FailureURL
	if failurePath == "" {
		failurePath = "/admin/login?err=external"
	}
	return &ConsoleHandler{
		svc:          opts.Svc,
		resolver:     opts.Resolver,
		sessionMgr:   opts.SessionMgr,
		gate:         opts.Gate,
		tenantByCode: opts.TenantByCode,
		tenantID:     opts.TenantID,
		baseURL:      opts.BaseURL,
		consoleURL:   consoleURL,
		loginURL:     consoleURL + loginPath,
		failureURL:   consoleURL + failurePath,
		cookieName:   opts.CookieName,
		cookieDomain: opts.CookieDomain,
		cookieSecure: opts.CookieSecure,
	}
}

// RegisterRoutes mounts the public console external-IdP routes. The caller
// MUST NOT prefix these with auth middleware — login runs before a session
// exists.
//
//	GET /auth/external             — enabled IdP list for the console login page
//	GET /auth/external/:code/start — 302 to the provider authorize URL
//	GET /auth/external/:code/callback — exchange + admin-gated login
func (h *ConsoleHandler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/auth/external")
	{
		g.GET("", h.list)
		g.GET("/:code/start", h.start)
		g.GET("/:code/callback", h.callback)
	}
}

func (h *ConsoleHandler) list(c *gin.Context) {
	tenantID := h.tenantID
	if code := c.Query("tenant"); code != "" && h.tenantByCode != nil {
		if tid := h.tenantByCode(c.Request.Context(), code); tid > 0 {
			tenantID = tid
		}
	}
	items, err := h.svc.ListPublic(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, "list idps: "+err.Error())
		return
	}
	response.OK(c, items)
}

func (h *ConsoleHandler) start(c *gin.Context) {
	code := c.Param("code")
	finalURL := c.Query("return_to")
	if finalURL == "" {
		finalURL = h.loginURL
	} else if len(finalURL) > 0 && finalURL[0] == '/' {
		finalURL = h.consoleURL + finalURL
	}
	redirectURI := fmt.Sprintf("%s/api/v1/console-public/auth/external/%s/callback", h.baseURL, code)
	authURL, err := h.svc.StartLogin(c.Request.Context(), h.tenantID, code, redirectURI, finalURL)
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL)
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

func (h *ConsoleHandler) callback(c *gin.Context) {
	state := c.Query("state")
	cbCode := c.Query("code")
	idp, identity, finalURL, err := h.svc.FinishLogin(c.Request.Context(), state, cbCode)
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL+"&reason="+url.QueryEscape(err.Error()))
		return
	}

	// auto-create is forced OFF for console: an unknown identity must not
	// silently provision an admin. No binding → ErrExternalUserNotLinked.
	userID, _, err := h.resolver.Resolve(c.Request.Context(), &ResolverInput{
		TenantID:     idp.TenantID,
		ProviderType: identity.ProviderType,
		ProviderID:   identity.ProviderID,
		ExternalID:   identity.ExternalID,
		Username:     identity.Username,
		DisplayName:  identity.DisplayName,
		Email:        identity.Email,
		Phone:        identity.Phone,
		Avatar:       identity.Avatar,
		Raw:          identity.Raw,
		AutoCreate:   false,
		DefaultOrgID: idp.DefaultOrgID,
	})
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL+"&reason="+url.QueryEscape(err.Error()))
		return
	}

	// Admin authorization + break-glass guard. Rejects non-admins and any
	// is_builtin account before a console session exists.
	if h.gate != nil {
		if gErr := h.gate(c.Request.Context(), idp.TenantID, userID); gErr != nil {
			c.Redirect(http.StatusFound, h.failureURL+"&reason="+url.QueryEscape(gErr.Error()))
			return
		}
	}

	sess, err := h.sessionMgr.Create(
		c.Request.Context(),
		session.NamespaceConsole,
		userID,
		idp.TenantID,
		c.ClientIP(),
		c.Request.UserAgent(),
		"external:"+identity.ProviderType,
	)
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL+"&reason=session")
		return
	}
	c.SetCookie(h.cookieName, sess.ID, 86400, "/", h.cookieDomain, h.cookieSecure, true)

	if finalURL == "" {
		finalURL = h.loginURL
	}
	c.Redirect(http.StatusFound, finalURL)
}

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

// IdentityResolver maps an external identity to a local user. Implemented
// by the user domain (see user.Service.ResolveExternalLogin) — defined here
// so this package does not import user/.
type IdentityResolver interface {
	Resolve(ctx context.Context, in *ResolverInput) (userID int64, username string, err error)
}

// ResolverInput mirrors user.ExternalLoginInput but kept package-local to
// avoid the cycle. Carries every field the user side needs to either link
// or auto-provision.
type ResolverInput struct {
	TenantID     int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	Username     string
	DisplayName  string
	Email        string
	Phone        string
	Avatar       string
	Raw          map[string]any
	AutoCreate   bool
	DefaultOrgID *int64
}

// PortalHandler exposes the public-facing routes that drive the OAuth
// redirect dance from the portal login page.
//
// Routes (mounted on the portal API group — NO auth middleware required):
//
//	GET  /auth/external                       — list enabled IdPs for the login page
//	GET  /auth/external/:code/start           — 302 to provider's authorize URL
//	GET  /auth/external/:code/callback        — exchange + login + 302 to final URL
type PortalHandler struct {
	svc          *Service
	resolver     IdentityResolver
	sessionMgr   *session.Manager
	tenantID     int64
	tenantByCode TenantCodeResolver
	baseURL      string // absolute backend URL used to build the IdP callback URI
	portalURL    string // absolute frontend URL prefix for post-login redirects
	loginURL     string // absolute URL where to bounce the browser when login succeeds
	failureURL   string // absolute URL where to bounce on error
	cookieName   string
	cookieDomain string
	cookieSecure bool
}

// TenantCodeResolver maps tenant code → id. Optional; when nil the handler
// uses the default tenantID for every request.
type TenantCodeResolver func(ctx context.Context, code string) int64

// PortalHandlerOpts groups the constructor parameters so adding more knobs
// later (e.g. consent screen) doesn't break callers.
//
// BaseURL is the backend's externally-reachable URL — used to build the
// callback URI that Lark/Teams/... will redirect back to (e.g.
// http://localhost:10050).
//
// PortalURL is the FRONTEND's externally-reachable URL — used as the prefix
// for LoginURL/FailureURL on redirects after the callback completes (e.g.
// http://localhost:3501). When empty, defaults to BaseURL so single-port
// production deployments (where API + UI live on the same host) keep working.
type PortalHandlerOpts struct {
	Svc          *Service
	Resolver     IdentityResolver
	SessionMgr   *session.Manager
	TenantID     int64
	TenantByCode TenantCodeResolver
	BaseURL      string // backend reachable URL, used for callback URI
	PortalURL    string // frontend reachable URL, used for post-login redirect
	LoginURL     string // path under PortalURL, e.g. /
	FailureURL   string // path under PortalURL, e.g. /login?err=external
	CookieName   string
	CookieDomain string
	CookieSecure bool
}

func NewPortalHandler(opts PortalHandlerOpts) *PortalHandler {
	portalURL := opts.PortalURL
	if portalURL == "" {
		// In single-port deployments (prod with API + UI on same origin) the
		// frontend lives at the same hostname as the API. Fall back to BaseURL.
		portalURL = opts.BaseURL
	}
	loginPath := opts.LoginURL
	if loginPath == "" {
		loginPath = "/"
	}
	failurePath := opts.FailureURL
	if failurePath == "" {
		failurePath = "/login?err=external"
	}
	return &PortalHandler{
		svc:          opts.Svc,
		resolver:     opts.Resolver,
		sessionMgr:   opts.SessionMgr,
		tenantByCode: opts.TenantByCode,
		tenantID:     opts.TenantID,
		baseURL:      opts.BaseURL,
		portalURL:    portalURL,
		loginURL:     portalURL + loginPath,
		failureURL:   portalURL + failurePath,
		cookieName:   opts.CookieName,
		cookieDomain: opts.CookieDomain,
		cookieSecure: opts.CookieSecure,
	}
}

// RegisterRoutes attaches the public routes onto the portal group. NOTE the
// caller MUST NOT prefix this with any auth middleware — these routes need
// to work for unauthenticated users.
func (h *PortalHandler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/auth/external")
	{
		g.GET("", h.list)
		g.GET("/:code/start", h.start)
		g.GET("/:code/callback", h.callback)
	}
}

// list returns the publicly-visible IdP list used by the portal login page
// to render social-login buttons.
//
// Multi-tenant: ?tenant=<code> filters the list to that tenant's IdPs.
// Empty falls back to the handler's default tenant.
func (h *PortalHandler) list(c *gin.Context) {
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

func (h *PortalHandler) start(c *gin.Context) {
	code := c.Param("code")
	finalURL := c.Query("return_to")
	if finalURL == "" {
		finalURL = h.loginURL
	} else if len(finalURL) > 0 && finalURL[0] == '/' {
		// Relative return_to → resolve against portalURL so callback
		// redirect always lands on the frontend host, not the backend.
		finalURL = h.portalURL + finalURL
	}
	redirectURI := fmt.Sprintf("%s/api/v1/portal/auth/external/%s/callback", h.baseURL, code)
	authURL, err := h.svc.StartLogin(c.Request.Context(), h.tenantID, code, redirectURI, finalURL)
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL)
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

func (h *PortalHandler) callback(c *gin.Context) {
	state := c.Query("state")
	cbCode := c.Query("code")
	idp, identity, finalURL, err := h.svc.FinishLogin(c.Request.Context(), state, cbCode)
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL+"&reason="+url.QueryEscape(err.Error()))
		return
	}

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
		AutoCreate:   idp.AutoCreate,
		DefaultOrgID: idp.DefaultOrgID,
	})
	if err != nil {
		c.Redirect(http.StatusFound, h.failureURL+"&reason="+url.QueryEscape(err.Error()))
		return
	}

	// Mint portal session.
	sess, err := h.sessionMgr.Create(
		c.Request.Context(),
		session.NamespacePortal,
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

	// Also mint a proto-scope session so SSO continues to work without
	// re-prompting at /protocol/oidc/authorize.
	if protoSess, err := h.sessionMgr.Create(
		c.Request.Context(),
		session.NamespaceProtocol,
		userID,
		idp.TenantID,
		c.ClientIP(),
		c.Request.UserAgent(),
		"external:"+identity.ProviderType,
	); err == nil {
		c.SetCookie("mxid_proto_sid", protoSess.ID, 24*60*60, "/", h.cookieDomain, h.cookieSecure, true)
	}

	if finalURL == "" {
		finalURL = h.loginURL
	}
	c.Redirect(http.StatusFound, finalURL)
}

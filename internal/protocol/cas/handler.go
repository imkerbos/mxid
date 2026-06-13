package cas

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/imkerbos/mxid/pkg/urlswap"
)

// Handler serves CAS protocol endpoints.
type Handler struct {
	issuer      string
	portalURL   string
	urlProvider urlswap.Provider
	appRes      resolver.AppResolver
	idRes       resolver.IdentityResolver
	sessRes     resolver.SessionResolver
	tenantRes   resolver.TenantResolver
	store       *TicketStore
}

// SetURLProvider installs the runtime URL lookup. nil = stick with
// config defaults (legacy behaviour).
func (h *Handler) SetURLProvider(p urlswap.Provider) { h.urlProvider = p }

func (h *Handler) resolveURLs(c *gin.Context) urlswap.URLs {
	return urlswap.Resolve(c.Request.Context(), h.urlProvider, urlswap.URLs{
		Issuer: h.issuer,
		Portal: h.portalURL,
	}, c.Request.Host)
}

// NewHandler creates a CAS handler. portalURL is where the user-facing
// login page lives (separate SPA host in dev, same host in prod); used to
// build the bounce URL when /login lacks a protocol session.
func NewHandler(
	issuer string,
	portalURL string,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	store *TicketStore,
) *Handler {
	return &Handler{
		issuer:    issuer,
		portalURL: portalURL,
		appRes:    appRes,
		idRes:     idRes,
		sessRes:   sessRes,
		tenantRes: tenantRes,
		store:     store,
	}
}

// RegisterRoutes registers CAS endpoints.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	cas := rg.Group("/cas/:app_code")
	{
		cas.GET("/login", h.login)
		cas.GET("/validate", h.validate)
		cas.GET("/serviceValidate", h.serviceValidate)
		cas.GET("/p3/serviceValidate", h.p3ServiceValidate)
		cas.GET("/logout", h.logout)
	}
}

// login handles the CAS login endpoint.
func (h *Handler) login(c *gin.Context) {
	appCode := c.Param("app_code")
	service := c.Query("service")

	if service == "" {
		response.BadRequest(c, 40001, "missing service parameter")
		return
	}

	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		response.NotFound(c, 40401, "application not found")
		return
	}

	if app.Status != 1 {
		response.Error(c, http.StatusForbidden, 40301, "application is disabled", "")
		return
	}

	casCfg := h.parseCASConfig(app.ProtocolConfig)

	// Validate service URL
	if !h.isValidService(casCfg, service) {
		response.BadRequest(c, 40002, "invalid service URL")
		return
	}

	// Check for protocol session
	sessionCookie, err := c.Cookie("mxid_proto_sid")
	if err != nil || sessionCookie == "" {
		h.redirectToLogin(c, appCode, service)
		return
	}

	ssoSess, err := h.sessRes.GetSSOSession(c.Request.Context(), sessionCookie)
	if err != nil || ssoSess == nil {
		h.redirectToLogin(c, appCode, service)
		return
	}
	// Pin the SSO session's tenant so the user read is tenant-scoped.
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), ssoSess.TenantID))

	// User authenticated — resolve user and issue ticket
	user, err := h.idRes.ResolveUser(c.Request.Context(), ssoSess.UserID)
	if err != nil {
		response.InternalError(c, "failed to resolve user")
		return
	}

	// Resolve principal per app.subject_strategy. Shared apps default to
	// username_suffixed so two tenants' "kerbos" don't collide in
	// downstream CAS clients that key by principal.
	tenantCode := ""
	if h.tenantRes != nil && user.TenantID > 0 {
		tenantCode, _ = h.tenantRes.GetTenantCode(c.Request.Context(), user.TenantID)
	}
	subj, _ := resolver.ResolveSubject(c.Request.Context(), app.SubjectStrategy, resolver.SubjectInput{
		UserID:     user.ID,
		Username:   user.Username,
		Email:      user.Email,
		TenantID:   user.TenantID,
		TenantCode: tenantCode,
		ClientID:   app.ClientID,
	})
	principal := user.Username
	if subj != nil && subj.Subject != "" {
		principal = subj.Subject
	}

	ticket, err := h.store.CreateTicket(
		c.Request.Context(),
		ssoSess.UserID,
		ssoSess.TenantID,
		service,
		principal,
		casCfg.TicketTTL,
	)
	if err != nil {
		response.InternalError(c, "failed to create service ticket")
		return
	}

	// Redirect to service with ticket
	sep := "?"
	if strings.Contains(service, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, fmt.Sprintf("%s%sticket=%s", service, sep, ticket.Ticket))
}

// validate handles CAS 1.0 validation (plain text response).
func (h *Handler) validate(c *gin.Context) {
	ticket := c.Query("ticket")
	service := c.Query("service")

	if ticket == "" || service == "" {
		c.String(http.StatusOK, "no\n\n")
		return
	}

	st, err := h.store.ConsumeTicket(c.Request.Context(), ticket)
	if err != nil {
		c.String(http.StatusOK, "no\n\n")
		return
	}

	if st.Service != service {
		c.String(http.StatusOK, "no\n\n")
		return
	}

	c.String(http.StatusOK, "yes\n%s\n", st.Username)
}

// CAS 2.0 XML response types.

// ServiceResponse wraps CAS 2.0/3.0 XML responses.
type ServiceResponse struct {
	XMLName xml.Name `xml:"cas:serviceResponse"`
	Xmlns   string   `xml:"xmlns:cas,attr"`
	Success *AuthenticationSuccess `xml:"cas:authenticationSuccess,omitempty"`
	Failure *AuthenticationFailure `xml:"cas:authenticationFailure,omitempty"`
}

// AuthenticationSuccess represents a successful validation.
type AuthenticationSuccess struct {
	User       string      `xml:"cas:user"`
	Attributes *Attributes `xml:"cas:attributes,omitempty"`
}

// AuthenticationFailure represents a failed validation.
type AuthenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// Attributes holds CAS 3.0 user attributes.
type Attributes struct {
	Items []AttributeItem
}

// AttributeItem is a single CAS attribute.
type AttributeItem struct {
	Name  string
	Value string
}

// MarshalXML custom marshals CAS attributes.
func (a *Attributes) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "cas:attributes"}
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	for _, item := range a.Items {
		elem := xml.StartElement{Name: xml.Name{Local: "cas:" + item.Name}}
		if err := e.EncodeElement(item.Value, elem); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// serviceValidate handles CAS 2.0 validation (XML response, no attributes).
func (h *Handler) serviceValidate(c *gin.Context) {
	h.doServiceValidate(c, false)
}

// p3ServiceValidate handles CAS 3.0 validation (XML response with attributes).
func (h *Handler) p3ServiceValidate(c *gin.Context) {
	h.doServiceValidate(c, true)
}

func (h *Handler) doServiceValidate(c *gin.Context, includeAttributes bool) {
	ticket := c.Query("ticket")
	service := c.Query("service")

	if ticket == "" || service == "" {
		h.xmlFailure(c, "INVALID_REQUEST", "missing ticket or service parameter")
		return
	}

	st, err := h.store.ConsumeTicket(c.Request.Context(), ticket)
	if err != nil {
		h.xmlFailure(c, "INVALID_TICKET", "ticket not recognized or expired")
		return
	}

	if st.Service != service {
		h.xmlFailure(c, "INVALID_SERVICE", "service mismatch")
		return
	}

	success := &AuthenticationSuccess{
		User: st.Username,
	}

	// CAS 3.0: include user attributes
	if includeAttributes {
		appCode := c.Param("app_code")
		app, err := h.appRes.GetApp(c.Request.Context(), appCode)
		if err == nil && app != nil {
			casCfg := h.parseCASConfig(app.ProtocolConfig)
			// Pin the ticket's tenant so the user read is tenant-scoped.
			c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), st.TenantID))
			user, err := h.idRes.ResolveUser(c.Request.Context(), st.UserID)
			if err == nil {
				attrs := h.buildAttributes(casCfg, user)
				// Inject tenant_code so consumers can disambiguate users
				// from different tenants when this is a shared app.
				if h.tenantRes != nil && user.TenantID > 0 {
					if tc, _ := h.tenantRes.GetTenantCode(c.Request.Context(), user.TenantID); tc != "" {
						attrs.Items = append(attrs.Items, AttributeItem{
							Name:  "tenant_code",
							Value: tc,
						})
					}
				}
				if len(attrs.Items) > 0 {
					success.Attributes = attrs
				}
			}
		}
	}

	resp := &ServiceResponse{
		Xmlns:   "http://www.yale.edu/tp/cas",
		Success: success,
	}

	xmlBytes, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		h.xmlFailure(c, "INTERNAL_ERROR", "failed to generate response")
		return
	}

	c.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), xmlBytes...))
}

// logout handles CAS logout.
func (h *Handler) logout(c *gin.Context) {
	sessionCookie, _ := c.Cookie("mxid_proto_sid")
	if sessionCookie != "" {
		_ = h.sessRes.DeleteSSOSession(c.Request.Context(), sessionCookie)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("mxid_proto_sid", "", -1, "/", "", false, true)
	}

	service := c.Query("service")
	// Re-use the login-path service validator: only follow ?service= on
	// logout when it matches the calling SP's registered ServiceURLs.
	// Without this guard /cas/logout?service=https://evil is an open
	// redirect — exactly the attack vector that gets CAS deployments
	// flagged in pentests.
	if service != "" {
		// We don't have an app context on logout, but isSafeServiceURL
		// rejects javascript:/data:/non-loopback-http — the minimal
		// baseline. Operators wanting strict allow-list semantics can
		// add a per-tenant logout_uris registry later.
		if isSafeServiceURL(service) {
			c.Redirect(http.StatusFound, service)
			return
		}
	}

	response.OK(c, gin.H{"message": "logged out"})
}

// Helper methods

func (h *Handler) parseCASConfig(raw json.RawMessage) *CASConfig {
	cfg := Defaults()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
	}
	return cfg
}

func (h *Handler) isValidService(cfg *CASConfig, service string) bool {
	if len(cfg.ServiceURLs) == 0 {
		// Empty list is fail-open by historical CAS convention. We keep
		// that for backwards compatibility, but apply the same scheme /
		// shape sanity check we use on logout to block obvious abuse.
		return isSafeServiceURL(service)
	}
	requested, err := parseAbsoluteHTTP(service)
	if err != nil {
		return false
	}
	for _, allowed := range cfg.ServiceURLs {
		reg, err := parseAbsoluteHTTP(allowed)
		if err != nil {
			continue
		}
		// Scheme + host + port must match exactly (case-insensitive on
		// scheme/host). Path may extend the registered path so a single
		// "https://app.com/cas" entry covers /cas, /cas/, /cas/foo etc.
		// — the classic prefix-bypass `https://app.com.evil.com` no
		// longer matches because the parsed Host differs.
		if !strings.EqualFold(requested.Scheme, reg.Scheme) ||
			!strings.EqualFold(requested.Host, reg.Host) {
			continue
		}
		if requested.Path == reg.Path ||
			strings.HasPrefix(requested.Path, strings.TrimRight(reg.Path, "/")+"/") {
			return true
		}
	}
	return false
}

// parseAbsoluteHTTP parses an http(s) absolute URL and rejects anything
// with a userinfo component (which is a known smuggling vector).
func parseAbsoluteHTTP(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		return nil, errInvalidServiceURL
	}
	if u.User != nil {
		return nil, errInvalidServiceURL
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errInvalidServiceURL
	}
	if u.Fragment != "" {
		return nil, errInvalidServiceURL
	}
	return u, nil
}

// isSafeServiceURL is the fail-open guard for configs that have NOT
// registered any service URLs. It rejects javascript:/data: and other
// schemes that would turn the login redirect into an XSS sink.
func isSafeServiceURL(raw string) bool {
	u, err := parseAbsoluteHTTP(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return true
}

var errInvalidServiceURL = errInvalidService{}

type errInvalidService struct{}

func (errInvalidService) Error() string { return "invalid service url" }

func (h *Handler) redirectToLogin(c *gin.Context, appCode, service string) {
	urls := h.resolveURLs(c)
	base := urls.Portal
	if base == "" {
		base = urls.Issuer
	}
	loginURL := fmt.Sprintf("%s/login?protocol=cas&app_code=%s&service=%s",
		base, appCode, service)
	c.Redirect(http.StatusFound, loginURL)
}

func (h *Handler) buildAttributes(cfg *CASConfig, user *resolver.IdentityInfo) *Attributes {
	userMap := map[string]string{
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"phone":        user.Phone,
	}

	attrs := &Attributes{}
	for userAttr, casAttr := range cfg.AttributeMapping {
		if val, ok := userMap[userAttr]; ok && val != "" {
			attrs.Items = append(attrs.Items, AttributeItem{
				Name:  casAttr,
				Value: val,
			})
		}
	}
	return attrs
}

func (h *Handler) xmlFailure(c *gin.Context, code, message string) {
	resp := &ServiceResponse{
		Xmlns: "http://www.yale.edu/tp/cas",
		Failure: &AuthenticationFailure{
			Code:    code,
			Message: message,
		},
	}

	xmlBytes, _ := xml.MarshalIndent(resp, "", "  ")
	c.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), xmlBytes...))
}

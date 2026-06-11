package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/urlswap"
)

// Handler serves SAML protocol endpoints.
type Handler struct {
	issuer      string
	portalURL   string
	urlProvider urlswap.Provider
	appRes      resolver.AppResolver
	idRes       resolver.IdentityResolver
	sessRes     resolver.SessionResolver
	tenantRes   resolver.TenantResolver
	builder     *AssertionBuilder
}

// SetURLProvider wires the runtime URL lookup. nil = stick with the
// issuer + portal URL captured at construction.
func (h *Handler) SetURLProvider(p urlswap.Provider) { h.urlProvider = p }

func (h *Handler) resolveURLs(ctx context.Context, reqHost string) urlswap.URLs {
	return urlswap.Resolve(ctx, h.urlProvider, urlswap.URLs{
		Issuer: h.issuer,
		Portal: h.portalURL,
	}, reqHost)
}

// NewHandler creates a SAML handler. portalURL is where the user-facing
// login lives; empty falls back to issuer (single-domain deploy).
func NewHandler(
	issuer string,
	portalURL string,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
) *Handler {
	if portalURL == "" {
		portalURL = issuer
	}
	return &Handler{
		issuer:    issuer,
		portalURL: portalURL,
		appRes:    appRes,
		idRes:     idRes,
		sessRes:   sessRes,
		tenantRes: tenantRes,
		builder:   NewAssertionBuilder(issuer),
	}
}

// RegisterRoutes registers SAML endpoints.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	saml := rg.Group("/saml/:app_code")
	{
		saml.GET("/metadata", h.metadata)
		saml.GET("/sso", h.ssoRedirect)
		saml.POST("/sso", h.ssoPost)
		// resume: portal redirects here after login. Carries the
		// in-flight request_id (the SP's AuthnRequest ID, decoded) and
		// relay_state so the response gets the matching InResponseTo
		// attribute. Avoids re-parsing the original SAMLRequest blob.
		saml.GET("/resume", h.ssoResume)
		saml.GET("/slo", h.slo)
		saml.POST("/slo", h.slo)
	}
}

// ssoResume picks up an SP-initiated flow after the user authenticated
// via the portal login page. Required because portal login is on the
// front-end and cannot replay a base64+DEFLATE SAMLRequest blob on its
// own; we pass the decoded ID forward instead.
func (h *Handler) ssoResume(c *gin.Context) {
	appCode := c.Param("app_code")
	requestID := c.Query("request_id")
	relayState := c.Query("relay_state")
	if requestID == "" {
		// No SP-initiated context to resume → behave like IdP-initiated.
		h.idpInitiatedSSO(c, appCode, relayState)
		return
	}
	h.processSSO(c, appCode, requestID, relayState)
}

// metadata returns the IDP metadata for the given application.
func (h *Handler) metadata(c *gin.Context) {
	appCode := c.Param("app_code")
	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		response.NotFound(c, 40401, "application not found")
		return
	}

	// Load signing cert. Lazy-mint when missing — covers SAML apps that
	// were created before auto-mint was added (old data) and any future
	// admin-driven cert delete. Operators expect /metadata to "just work"
	// as soon as the app exists, matching Keycloak / Okta behaviour.
	certs, err := h.appRes.ListCerts(c.Request.Context(), app.ID)
	if err != nil {
		response.InternalError(c, "list certs: "+err.Error())
		return
	}
	if len(certs) == 0 {
		minted, mintErr := h.appRes.MintSigningCert(c.Request.Context(), app.ID)
		if mintErr != nil {
			response.InternalError(c, "no signing cert and lazy-mint failed: "+mintErr.Error())
			return
		}
		if minted == nil {
			response.InternalError(c, "no signing cert and lazy-mint returned nil")
			return
		}
		certs = []*resolver.CertConfig{minted}
	}

	// Strip PEM armor for X509 cert in metadata. Accept either CERTIFICATE
	// (correct, X.509 self-signed wrapping the RSA key — what SAML wants)
	// or PUBLIC KEY (legacy; pre-cert key_service rows). Strip every newline
	// too so the resulting base64 is a single contiguous blob.
	certPEM := certs[0].PublicKey
	certPEM = strings.ReplaceAll(certPEM, "-----BEGIN CERTIFICATE-----", "")
	certPEM = strings.ReplaceAll(certPEM, "-----END CERTIFICATE-----", "")
	certPEM = strings.ReplaceAll(certPEM, "-----BEGIN PUBLIC KEY-----", "")
	certPEM = strings.ReplaceAll(certPEM, "-----END PUBLIC KEY-----", "")
	certPEM = strings.ReplaceAll(certPEM, "\n", "")
	certPEM = strings.ReplaceAll(certPEM, "\r", "")
	certPEM = strings.TrimSpace(certPEM)

	// Resolve URLs based on request host so the SP receives whatever
	// canonical entry the operator configured (nginx :3500 instead of the
	// raw backend :10050). Falls back to h.issuer when no swap applies.
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	entityID := urls.Issuer
	ssoURL := fmt.Sprintf("%s/protocol/saml/%s/sso", entityID, appCode)
	sloURL := fmt.Sprintf("%s/protocol/saml/%s/slo", entityID, appCode)

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="%s">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
                     protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                          Location="%s"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                          Location="%s"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                          Location="%s"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                          Location="%s"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, entityID, certPEM, sloURL, sloURL, ssoURL, ssoURL)

	c.Data(http.StatusOK, "application/xml", []byte(metadata))
}

// ssoRedirect handles SSO via HTTP-Redirect binding.
func (h *Handler) ssoRedirect(c *gin.Context) {
	appCode := c.Param("app_code")
	samlRequest := c.Query("SAMLRequest")
	relayState := c.Query("RelayState")

	if samlRequest == "" {
		// IDP-Initiated SSO (no AuthnRequest)
		h.idpInitiatedSSO(c, appCode, relayState)
		return
	}

	// Decode SAMLRequest (base64 + deflate for redirect binding)
	requestID, err := extractRequestID(samlRequest)
	if err != nil {
		response.BadRequest(c, 40001, "invalid SAMLRequest")
		return
	}

	h.processSSO(c, appCode, requestID, relayState)
}

// ssoPost handles SSO via HTTP-POST binding.
func (h *Handler) ssoPost(c *gin.Context) {
	appCode := c.Param("app_code")
	samlRequest := c.PostForm("SAMLRequest")
	relayState := c.PostForm("RelayState")

	if samlRequest == "" {
		h.idpInitiatedSSO(c, appCode, relayState)
		return
	}

	requestID, err := extractRequestID(samlRequest)
	if err != nil {
		response.BadRequest(c, 40001, "invalid SAMLRequest")
		return
	}

	h.processSSO(c, appCode, requestID, relayState)
}

// processSSO is the shared SSO logic for both bindings.
func (h *Handler) processSSO(c *gin.Context, appCode, requestID, relayState string) {
	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		response.NotFound(c, 40401, "application not found")
		return
	}

	if app.Status != 1 {
		response.Error(c, http.StatusForbidden, 40301, "application is disabled", "")
		return
	}

	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)

	// Session lookup: try the dedicated protocol cookie first, fall back
	// to the portal cookie. IdP-initiated SSO from the portal "我的应用"
	// page lands here with only the portal session present — bouncing
	// such users through /login defeats SSO. Both cookies resolve through
	// the same SessionResolver, so the assertion is built from whichever
	// session is valid.
	var ssoSess *resolver.SSOSession
	if sc, cerr := c.Cookie("mxid_proto_sid"); cerr == nil && sc != "" {
		ssoSess, _ = h.sessRes.GetSSOSession(c.Request.Context(), sc)
	}
	if ssoSess == nil {
		if pc, cerr := c.Cookie("mxid_portal_sid"); cerr == nil && pc != "" {
			ssoSess, _ = h.sessRes.GetSSOSession(c.Request.Context(), pc)
		}
	}
	if ssoSess == nil {
		h.redirectToLogin(c, appCode, requestID, relayState)
		return
	}

	// User authenticated — build assertion
	user, err := h.idRes.ResolveUser(c.Request.Context(), ssoSess.UserID)
	if err != nil {
		response.InternalError(c, "failed to resolve user identity")
		return
	}

	// Resolve subject according to app.subject_strategy. The strategy wins
	// over the legacy samlCfg.NameIDFormat — shared apps that picked
	// username_suffixed produce safe NameIDs across tenants.
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
	var nameIDValue string
	if subj != nil && subj.Subject != "" {
		nameIDValue = subj.Subject
	} else {
		nameIDValue = h.resolveNameID(samlCfg.NameIDFormat, user)
	}

	// Build attribute map (adds tenant_code + adjusted username for cross-tenant disambiguation).
	attrs := h.buildAttributes(samlCfg, user)
	if tenantCode != "" {
		attrs["tenant_code"] = tenantCode
	}
	if subj != nil && subj.DisplayUsername != "" {
		attrs["username"] = subj.DisplayUsername
	}

	// Resolve issuer by request host so a SP that fetched metadata from
	// host X gets a Response signed-as / issued-by host X. Without this
	// the SP rejects the Response with "Invalid issuer ... expected X
	// got Y" the moment it's reached via a non-canonical host.
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	ttl := time.Duration(samlCfg.SessionTTL) * time.Second
	resp, err := h.builder.BuildResponse(&BuildParams{
		RequestID:    requestID,
		ACSURL:       samlCfg.ACSURL,
		SPEntityID:   samlCfg.SPEntityID,
		NameIDFormat: samlCfg.NameIDFormat,
		NameIDValue:  nameIDValue,
		User:         user,
		Attributes:   attrs,
		TTL:          ttl,
		Issuer:       urls.Issuer,
	})
	if err != nil {
		response.InternalError(c, "failed to build SAML response")
		return
	}

	// Load the signing key for this app + build SignOptions when the
	// admin asked for signed Responses (default true). Loading early so
	// 500s point at "no cert" rather than failing inside EncodeResponse.
	var signOpts *SignOptions
	if samlCfg.SignResponse || samlCfg.SignAssertions {
		signOpts, err = h.loadSignOptions(c.Request.Context(), app.ID)
		if err != nil {
			response.InternalError(c, "failed to load signing key: "+err.Error())
			return
		}
	}

	// Encode response
	encodedResp, err := EncodeResponse(resp, signOpts)
	if err != nil {
		response.InternalError(c, "failed to encode SAML response")
		return
	}

	// Return auto-submit form (POST binding to SP's ACS)
	h.renderPostForm(c, samlCfg.ACSURL, encodedResp, relayState)
}

// idpInitiatedSSO handles IDP-Initiated SSO (no AuthnRequest).
func (h *Handler) idpInitiatedSSO(c *gin.Context, appCode, relayState string) {
	h.processSSO(c, appCode, "", relayState)
}

// slo handles Single Logout.
//
// Open-redirect hardening:
//  1. Parse Issuer from the SAML LogoutRequest (if present) and look up
//     the SP's configured SLOURL / ACSURL.
//  2. RelayState is only followed when:
//     (a) it matches the SP's SLOURL host exactly, OR
//     (b) the SP cannot be identified (no SAMLRequest, malformed XML)
//     AND the URL passes the baseline shape check.
//
// Without (a) the spec-allowed "return RelayState to the user agent" turns
// into an open redirect because RelayState is attacker-controlled.
func (h *Handler) slo(c *gin.Context) {
	sessionCookie, _ := c.Cookie("mxid_proto_sid")

	if sessionCookie != "" {
		_ = h.sessRes.DeleteSSOSession(c.Request.Context(), sessionCookie)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("mxid_proto_sid", "", -1, "/", "", false, true)
	}

	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	if relayState != "" && h.isAllowedSLORedirect(c, relayState) {
		c.Redirect(http.StatusFound, relayState)
		return
	}

	response.OK(c, gin.H{"message": "logged out"})
}

// isAllowedSLORedirect runs the layered SLO redirect check described on
// slo(). The host-match against the SP's SLOURL is the load-bearing
// guarantee; the baseline-shape fallback only fires when no SP context
// is available and exists to keep dev / metadata-less flows working.
func (h *Handler) isAllowedSLORedirect(c *gin.Context, relayState string) bool {
	target, err := url.Parse(relayState)
	if err != nil || !isSafeSLORedirect(relayState) {
		return false
	}

	app := h.lookupSLOIssuer(c)
	if app == nil {
		// No issuer info — fall back to baseline shape check so legacy
		// flows that didn't go through a LogoutRequest still work.
		return true
	}

	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)
	for _, candidate := range []string{samlCfg.SLOURL, samlCfg.ACSURL} {
		regURL, err := url.Parse(candidate)
		if err != nil || regURL.Host == "" {
			continue
		}
		if strings.EqualFold(regURL.Host, target.Host) &&
			strings.EqualFold(regURL.Scheme, target.Scheme) {
			return true
		}
	}
	return false
}

// lookupSLOIssuer pulls the SAMLRequest off the SLO request, extracts the
// Issuer element and resolves it to an AppConfig. Returns nil on any
// failure — caller treats that as "unknown SP" and falls back to the
// baseline shape check.
func (h *Handler) lookupSLOIssuer(c *gin.Context) *resolver.AppConfig {
	encoded := c.Query("SAMLRequest")
	if encoded == "" {
		encoded = c.PostForm("SAMLRequest")
	}
	if encoded == "" {
		return nil
	}
	issuer, err := extractRequestIssuer(encoded)
	if err != nil || issuer == "" {
		return nil
	}
	// AppResolver.GetApp uses identifier (code OR client_id OR
	// entity_id); the SP's SAML EntityID lives in protocol_config.
	// We probe by entity_id via the resolver's ProtocolConfig scan if
	// available; otherwise the lookup returns nil and we fall back.
	app, err := h.appRes.GetApp(c.Request.Context(), issuer)
	if err != nil {
		return nil
	}
	return app
}

// extractRequestIssuer decodes a SAML LogoutRequest / AuthnRequest and
// returns the saml:Issuer string. Same encoding sandwich as
// extractRequestID — pulls a different element. Returns empty when the
// payload does not carry an issuer.
func extractRequestIssuer(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
			if decoded, err = base64.URLEncoding.DecodeString(encoded); err != nil {
				if decoded, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
					return "", fmt.Errorf("decode SAMLRequest base64: %w", err)
				}
			}
		}
	}
	xmlBytes := decoded
	if inflated, ierr := io.ReadAll(flate.NewReader(bytes.NewReader(decoded))); ierr == nil && len(inflated) > 0 {
		xmlBytes = inflated
	}
	type request struct {
		Issuer string `xml:"Issuer"`
	}
	var req request
	if err := safeXMLDecode(xmlBytes, &req); err != nil {
		return "", fmt.Errorf("parse LogoutRequest: %w", err)
	}
	return strings.TrimSpace(req.Issuer), nil
}

// isSafeSLORedirect rejects schemes / shapes that turn the SLO endpoint
// into an open-redirect oracle. It does NOT verify that the target is a
// registered SP — SAML metadata stores SLOURL per app but the SLO request
// here lacks the issuer context to look it up reliably. This is the OWASP
// "block obviously dangerous shapes" baseline; high-assurance deployments
// should additionally check that the host appears in some app's SLOURL.
func isSafeSLORedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// Helper methods

func (h *Handler) parseSAMLConfig(raw json.RawMessage) *SAMLConfig {
	cfg := Defaults()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
	}
	return cfg
}

func (h *Handler) resolveNameID(format string, user *resolver.IdentityInfo) string {
	switch format {
	case NameIDEmail:
		return user.Email
	case NameIDPersistent:
		return fmt.Sprintf("%d", user.ID)
	default:
		return user.Username
	}
}

func (h *Handler) buildAttributes(cfg *SAMLConfig, user *resolver.IdentityInfo) map[string]string {
	attrs := make(map[string]string)
	userMap := map[string]string{
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"phone":        user.Phone,
		"avatar":       user.Avatar,
	}

	for userAttr, samlAttr := range cfg.AttributeMapping {
		if val, ok := userMap[userAttr]; ok && val != "" {
			attrs[samlAttr] = val
		}
	}
	return attrs
}

// loadSignOptions fetches the active signing cert for the app and
// returns parsed key + PEM. Private key is master-key-decrypted upstream
// by the cert adapter; here we just parse PEM into *rsa.PrivateKey.
func (h *Handler) loadSignOptions(ctx context.Context, appID int64) (*SignOptions, error) {
	certs, err := h.appRes.ListCerts(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	if len(certs) == 0 {
		// Lazy mint to match metadata handler behaviour — operators expect
		// signing to "just work" once an app exists.
		minted, mErr := h.appRes.MintSigningCert(ctx, appID)
		if mErr != nil {
			return nil, fmt.Errorf("mint signing cert: %w", mErr)
		}
		certs = []*resolver.CertConfig{minted}
	}
	c := certs[0]
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("private key PEM not decodable")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if any, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		if key, ok = any.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("private key not RSA")
		}
	} else {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &SignOptions{Key: key, CertPEM: c.PublicKey}, nil
}

func (h *Handler) redirectToLogin(c *gin.Context, appCode, requestID, relayState string) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	base := urls.Portal
	if base == "" {
		base = urls.Issuer
	}
	loginURL := fmt.Sprintf("%s/login?protocol=saml&app_code=%s&request_id=%s&relay_state=%s",
		base, appCode, requestID, relayState)
	c.Redirect(http.StatusFound, loginURL)
}

func (h *Handler) renderPostForm(c *gin.Context, acsURL, samlResponse, relayState string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit();">
  <form method="POST" action="%s">
    <input type="hidden" name="SAMLResponse" value="%s"/>
    <input type="hidden" name="RelayState" value="%s"/>
    <noscript><input type="submit" value="Continue"/></noscript>
  </form>
</body>
</html>`, acsURL, samlResponse, relayState)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// extractRequestID decodes a SAMLRequest and extracts the ID attribute.
//
// Encoding sandwich per SAML 2.0 bindings (§3.4.4.1 for HTTP-Redirect,
// §3.5.4 for HTTP-POST):
//
//   HTTP-Redirect: DEFLATE → base64 → URL-encode
//   HTTP-POST:     base64 → form-encode (no DEFLATE)
//
// We try multiple base64 alphabets (std + URL + raw) so a buggy SP that
// chose the wrong variant still works. After base64-decode we attempt
// DEFLATE inflate; if it fails we treat the bytes as the raw XML (POST
// binding path) and parse directly.
func extractRequestID(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
			if decoded, err = base64.URLEncoding.DecodeString(encoded); err != nil {
				if decoded, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
					return "", fmt.Errorf("decode SAMLRequest base64: %w", err)
				}
			}
		}
	}

	// Try DEFLATE inflate (HTTP-Redirect). flate.NewReader expects raw
	// deflate stream with no zlib wrapper — exactly what SAML 2.0 specifies.
	xmlBytes := decoded
	if inflated, ierr := io.ReadAll(flate.NewReader(bytes.NewReader(decoded))); ierr == nil && len(inflated) > 0 {
		xmlBytes = inflated
	}

	type AuthnRequest struct {
		ID string `xml:"ID,attr"`
	}
	var req AuthnRequest
	if err := safeXMLDecode(xmlBytes, &req); err != nil {
		return "", fmt.Errorf("parse AuthnRequest: %w", err)
	}
	if req.ID == "" {
		return "", fmt.Errorf("AuthnRequest missing ID attribute")
	}
	return req.ID, nil
}

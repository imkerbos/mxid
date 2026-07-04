package saml

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	dsig "github.com/russellhaering/goxmldsig"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/response"
)

// SAML 2.0 top-level status codes (§3.2.2.2).
const (
	statusResponder   = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	statusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
)

// samlPostFormTmpl is the auto-submitting HTTP-POST binding form used to deliver
// the (error) Response to the SP's ACS. Values are attribute-escaped by
// html/template. Mirrors the form crewjam renders for success responses.
var samlPostFormTmpl = template.Must(template.New("samlpost").Parse(
	`<!DOCTYPE html><html><body onload="document.forms[0].submit()">` +
		`<form method="post" action="{{.ACS}}">` +
		`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"/>` +
		`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}"/>{{end}}` +
		`<noscript><input type="submit" value="Continue"/></noscript>` +
		`</form></body></html>`))

// redirectToConsent bounces an SP-initiated SAML login to the portal confirm
// page. return_to is the /resume URL (request_id + relay_state) so the page's
// approve replays it carrying sso_confirm and its cancel appends sso_deny=1.
// /resume rebuilds the assertion from the SP's registered metadata, so the
// original SAMLRequest blob does not need to survive the bounce. No scope param
// — SAML has none, so the page renders a pure "log in to App X?" confirmation.
func (h *Handler) redirectToConsent(c *gin.Context, appID int64, appCode, requestID, relayState string) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	base := urls.Portal
	if base == "" {
		base = urls.Issuer
	}
	resumeURL := fmt.Sprintf("%s/protocol/saml/%s/resume?request_id=%s&relay_state=%s",
		urls.Issuer, url.PathEscape(appCode), url.QueryEscape(requestID), url.QueryEscape(relayState))
	consentURL := fmt.Sprintf("%s/consent?app_id=%d&return_to=%s",
		base, appID, url.QueryEscape(resumeURL))
	c.Redirect(http.StatusFound, consentURL)
}

// writeSAMLError delivers a signed SAML error Response (Responder / AuthnFailed)
// to the SP's ACS via the HTTP-POST binding — the spec-compliant way to tell the
// SP the user cancelled, instead of a bare IdP-side page. InResponseTo echoes the
// SP's AuthnRequest ID; RelayState is preserved.
func (h *Handler) writeSAMLError(c *gin.Context, appCode string, appID int64, samlCfg *SAMLConfig, requestID, relayState string) {
	key, cert, err := h.loadKeyAndCert(c.Request.Context(), appID)
	if err != nil {
		h.logger.Error("saml error response: load signing key failed",
			zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to load signing key", err)
		return
	}
	if samlCfg.ACSURL == "" {
		h.logger.Warn("saml error response: no ACS URL configured",
			zap.String("app_code", appCode), zap.Int64("app_id", appID))
		response.InternalError(c, "no assertion consumer endpoint for this application")
		return
	}

	entityID := h.resolveURLs(c.Request.Context(), c.Request.Host).Issuer
	now := time.Now()
	resp := &crewjam.Response{
		Destination:  samlCfg.ACSURL,
		ID:           "id-" + randomHex(20),
		InResponseTo: requestID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  entityID,
		},
		Status: crewjam.Status{
			StatusCode: crewjam.StatusCode{
				Value:      statusResponder,
				StatusCode: &crewjam.StatusCode{Value: statusAuthnFailed},
			},
			StatusMessage: &crewjam.StatusMessage{Value: "user cancelled the login"},
		},
	}

	el := resp.Element()
	signedEl, err := signSAMLElement(el, key, cert)
	if err != nil {
		h.logger.Error("saml error response: sign failed",
			zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to sign SAML response", err)
		return
	}
	// Move the produced Signature onto the Response and re-render, matching how
	// crewjam attaches the enveloped signature to the response element.
	sigEl := signedEl.ChildElements()[len(signedEl.ChildElements())-1]
	resp.Signature = sigEl
	el = resp.Element()

	doc := etree.NewDocument()
	doc.SetRoot(el)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		h.logger.Error("saml error response: marshal failed",
			zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to marshal SAML response", err)
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	// X-Frame-Options DENY is set globally; the auto-post form is top-level, fine.
	if err := samlPostFormTmpl.Execute(c.Writer, struct {
		ACS          string
		SAMLResponse string
		RelayState   string
	}{
		ACS:          samlCfg.ACSURL,
		SAMLResponse: base64.StdEncoding.EncodeToString(xmlBytes),
		RelayState:   relayState,
	}); err != nil {
		h.logger.Error("saml error response: render form failed",
			zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
	}
}

// signSAMLElement enveloped-signs a SAML element with the app's RSA key, using
// the same algorithm/canonicalisation crewjam uses for success responses
// (exclusive C14N, RSA-SHA256) so SPs validate error and success alike.
func signSAMLElement(el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate) (*etree.Element, error) {
	keyStore := dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	})
	ctx := dsig.NewDefaultSigningContext(keyStore)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	return ctx.SignEnveloped(el)
}

// SAML SP metadata parser. Reads an EntityDescriptor XML produced by an SP
// (Nextcloud / Keycloak SP / Auth0 SP-mode / etc.) and extracts the four
// fields the MXID console SAML config needs:
//
//   - sp_entity_id (EntityDescriptor[@entityID])
//   - acs_url      (AssertionConsumerService[@Location], HTTP-POST preferred)
//   - slo_url      (SingleLogoutService[@Location], HTTP-Redirect preferred)
//   - sp_cert      (KeyDescriptor[@use=signing] X509Certificate, PEM-armored)
//   - name_id_format (first NameIDFormat in SPSSODescriptor)
//
// Operators paste the SP metadata XML (or upload the .xml file, or hand us a
// URL we fetch ourselves) and we patch the app's protocol_config in one
// shot — same UX as Keycloak's "Import" button.
package saml

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// SAML 2.0 binding URNs. Go's encoding/xml matches element names against
// `xmlns + " " + local`, so the struct tags below carry the OASIS metadata
// + xmldsig namespace URIs verbatim.
const (
	bindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
)

// SPMetadata is the parsed shape we keep around long enough to patch
// protocol_config. Fields can be empty when the SP metadata omits them
// (e.g. SPs that don't support SLO won't carry a SingleLogoutService).
type SPMetadata struct {
	EntityID     string
	ACSURL       string
	SLOURL       string
	NameIDFormat string
	X509CertPEM  string
}

// XML schema mappings — only the elements we actually consume. Anything else
// is silently ignored so future SAML profile extensions don't break parsing.
type spXMLEntityDescriptor struct {
	XMLName  xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string               `xml:"entityID,attr"`
	SPSSO    *spXMLSPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

type spXMLSPSSODescriptor struct {
	KeyDescriptors []spXMLKeyDescriptor              `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	NameIDFormats  []string                          `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	ACS            []spXMLIndexedEndpoint            `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	SLO            []spXMLEndpoint                   `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
}

type spXMLEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type spXMLIndexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

type spXMLKeyDescriptor struct {
	Use     string         `xml:"use,attr"`
	KeyInfo spXMLKeyInfo   `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type spXMLKeyInfo struct {
	X509Data spXMLX509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type spXMLX509Data struct {
	Certificates []string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

// ParseSPMetadata parses an SP EntityDescriptor XML payload. Returns
// ErrInvalidSPMetadata when the document is not a SAML 2.0 SP metadata
// document with at least an entityID + SPSSODescriptor.
//
// Binding preferences:
//   - ACS: HTTP-POST > HTTP-Redirect > first available
//   - SLO: HTTP-Redirect > HTTP-POST > first available
//
// Cert preference: KeyDescriptor with use="signing", falling back to a
// descriptor with no `use` attribute (per spec it means both signing and
// encryption), finally to the first certificate present.
func ParseSPMetadata(raw []byte) (*SPMetadata, error) {
	if len(raw) == 0 {
		return nil, ErrInvalidSPMetadata("empty document")
	}
	var ed spXMLEntityDescriptor
	// Route through safeXMLDecode so DOCTYPE / external entity / charset
	// smuggling all get rejected uniformly — same posture as the SAML
	// AuthnRequest parser.
	if err := safeXMLDecode(raw, &ed); err != nil {
		return nil, fmt.Errorf("parse sp metadata: %w", err)
	}
	if ed.EntityID == "" {
		return nil, ErrInvalidSPMetadata("missing entityID")
	}
	if ed.SPSSO == nil {
		return nil, ErrInvalidSPMetadata("missing SPSSODescriptor (is this an IdP metadata?)")
	}

	out := &SPMetadata{EntityID: ed.EntityID}

	// ACS endpoint — POST preferred (the dominant binding for browser flows).
	for _, a := range ed.SPSSO.ACS {
		if a.Binding == bindingHTTPPost {
			out.ACSURL = a.Location
			break
		}
	}
	if out.ACSURL == "" {
		for _, a := range ed.SPSSO.ACS {
			if a.Binding == bindingHTTPRedirect {
				out.ACSURL = a.Location
				break
			}
		}
	}
	if out.ACSURL == "" && len(ed.SPSSO.ACS) > 0 {
		out.ACSURL = ed.SPSSO.ACS[0].Location
	}

	// SLO endpoint — Redirect preferred (Nextcloud / Keycloak default).
	for _, s := range ed.SPSSO.SLO {
		if s.Binding == bindingHTTPRedirect {
			out.SLOURL = s.Location
			break
		}
	}
	if out.SLOURL == "" {
		for _, s := range ed.SPSSO.SLO {
			if s.Binding == bindingHTTPPost {
				out.SLOURL = s.Location
				break
			}
		}
	}
	if out.SLOURL == "" && len(ed.SPSSO.SLO) > 0 {
		out.SLOURL = ed.SPSSO.SLO[0].Location
	}

	// NameID format — first declared one.
	if len(ed.SPSSO.NameIDFormats) > 0 {
		out.NameIDFormat = strings.TrimSpace(ed.SPSSO.NameIDFormats[0])
	}

	// Certificate — signing preferred, falling back to bare (no `use`) then any.
	var pickCert func() string
	pickCert = func() string {
		for _, k := range ed.SPSSO.KeyDescriptors {
			if k.Use == "signing" && len(k.KeyInfo.X509Data.Certificates) > 0 {
				return k.KeyInfo.X509Data.Certificates[0]
			}
		}
		for _, k := range ed.SPSSO.KeyDescriptors {
			if k.Use == "" && len(k.KeyInfo.X509Data.Certificates) > 0 {
				return k.KeyInfo.X509Data.Certificates[0]
			}
		}
		for _, k := range ed.SPSSO.KeyDescriptors {
			if len(k.KeyInfo.X509Data.Certificates) > 0 {
				return k.KeyInfo.X509Data.Certificates[0]
			}
		}
		return ""
	}
	if cert := pickCert(); cert != "" {
		out.X509CertPEM = wrapPEMCertificate(cert)
	}

	return out, nil
}

// wrapPEMCertificate normalises a raw base64 X.509 (the form found inside
// <ds:X509Certificate>) into a PEM-armored block. SPs sometimes paste the
// base64 already PEM-wrapped; we strip and re-wrap deterministically.
func wrapPEMCertificate(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "-----BEGIN CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "-----END CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return ""
	}
	// Re-wrap at 64 chars per line — common convention for PEM.
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	for i := 0; i < len(s); i += 64 {
		end := min(i+64, len(s))
		b.WriteString(s[i:end])
		b.WriteString("\n")
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String()
}

// ErrInvalidSPMetadata is returned when an XML document is parseable but
// fails SAML 2.0 SP metadata schema checks. Wraps the original reason.
type ErrInvalidSPMetadata string

func (e ErrInvalidSPMetadata) Error() string { return "invalid SP metadata: " + string(e) }

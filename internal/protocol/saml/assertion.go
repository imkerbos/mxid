package saml

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML XML namespace constants.
const (
	NsSAML    = "urn:oasis:names:tc:SAML:2.0:assertion"
	NsSAMLP   = "urn:oasis:names:tc:SAML:2.0:protocol"
	NsXMLDSig = "http://www.w3.org/2000/09/xmldsig#"
)

// Response represents a SAML 2.0 Response.
type Response struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr,omitempty"`
	Issuer       Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// Issuer represents the SAML Issuer element.
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// Status represents the SAML Status element.
type Status struct {
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

// StatusCode represents the SAML StatusCode element.
type StatusCode struct {
	Value string `xml:"Value,attr"`
}

// Assertion represents a SAML Assertion.
type Assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string              `xml:"ID,attr"`
	Version            string              `xml:"Version,attr"`
	IssueInstant       string              `xml:"IssueInstant,attr"`
	Issuer             Issuer              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            Subject             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatement     AuthnStatement      `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatement AttributeStatement  `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// Subject represents the SAML Subject.
type Subject struct {
	NameID              NameID              `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

// NameID represents the SAML NameID element.
type NameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

// SubjectConfirmation represents the SAML SubjectConfirmation.
type SubjectConfirmation struct {
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

// SubjectConfirmationData holds confirmation data.
type SubjectConfirmationData struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
}

// Conditions represents assertion validity conditions.
type Conditions struct {
	NotBefore            string               `xml:"NotBefore,attr"`
	NotOnOrAfter         string               `xml:"NotOnOrAfter,attr"`
	AudienceRestriction  AudienceRestriction  `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

// AudienceRestriction holds audience restrictions.
type AudienceRestriction struct {
	Audience string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// AuthnStatement represents an authentication statement.
type AuthnStatement struct {
	AuthnInstant string       `xml:"AuthnInstant,attr"`
	SessionIndex string       `xml:"SessionIndex,attr"`
	AuthnContext AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
}

// AuthnContext holds the authentication context.
type AuthnContext struct {
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

// AttributeStatement holds user attributes.
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Attribute represents a SAML attribute.
type Attribute struct {
	Name         string           `xml:"Name,attr"`
	NameFormat   string           `xml:"NameFormat,attr"`
	Values       []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// AttributeValue holds the value of a SAML attribute.
//
// We deliberately omit the xsi:type attribute. SAML core says
// xsi:type is optional, and emitting it forces the IdP to declare
// xmlns:xs + xmlns:xsi somewhere — but exclusive c14n during signing
// strips namespace declarations not visibly used as element / attribute
// prefixes, breaking strict SP validation downstream. Plain chardata
// values are accepted by every SP we target (BookStack, Nextcloud
// user_saml, SimpleSAMLphp, Auth0 SP, Keycloak SP).
type AttributeValue struct {
	Value string `xml:",chardata"`
}

// AssertionBuilder creates SAML assertions.
type AssertionBuilder struct {
	issuer string
}

// NewAssertionBuilder creates a new builder.
func NewAssertionBuilder(issuer string) *AssertionBuilder {
	return &AssertionBuilder{issuer: issuer}
}

// BuildParams holds parameters for building a SAML response.
type BuildParams struct {
	RequestID    string
	ACSURL       string
	SPEntityID   string
	NameIDFormat string
	NameIDValue  string
	SessionIndex string
	User         *resolver.IdentityInfo
	Attributes   map[string]string
	TTL          time.Duration
	// Issuer optionally overrides the AssertionBuilder's default issuer.
	// Set to the request-resolved IdP base URL so the SAML Response
	// carries the same host as the IdP metadata served to this SP. SPs
	// that strictly compare expected IdP issuer reject any mismatch.
	Issuer string
}

// BuildResponse creates a complete SAML Response with Assertion.
func (b *AssertionBuilder) BuildResponse(params *BuildParams) (*Response, error) {
	now := time.Now().UTC()
	expiry := now.Add(params.TTL)
	responseID := "_" + uuid.New().String()
	assertionID := "_" + uuid.New().String()

	if params.SessionIndex == "" {
		params.SessionIndex = "_" + uuid.New().String()
	}

	// Build attributes
	var attrs []Attribute
	for name, value := range params.Attributes {
		if value == "" {
			continue
		}
		attrs = append(attrs, Attribute{
			Name:       name,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{Value: value},
			},
		})
	}

	issuer := params.Issuer
	if issuer == "" {
		issuer = b.issuer
	}
	resp := &Response{
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  params.ACSURL,
		InResponseTo: params.RequestID,
		Issuer:       Issuer{Value: issuer},
		Status: Status{
			StatusCode: StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"},
		},
		Assertion: Assertion{
			ID:           assertionID,
			Version:      "2.0",
			IssueInstant: now.Format(time.RFC3339),
			Issuer:       Issuer{Value: issuer},
			Subject: Subject{
				NameID: NameID{
					Format: params.NameIDFormat,
					Value:  params.NameIDValue,
				},
				SubjectConfirmation: SubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						NotOnOrAfter: expiry.Format(time.RFC3339),
						Recipient:    params.ACSURL,
						InResponseTo: params.RequestID,
					},
				},
			},
			Conditions: Conditions{
				NotBefore:    now.Add(-5 * time.Minute).Format(time.RFC3339),
				NotOnOrAfter: expiry.Format(time.RFC3339),
				AudienceRestriction: AudienceRestriction{
					Audience: params.SPEntityID,
				},
			},
			AuthnStatement: AuthnStatement{
				AuthnInstant: now.Format(time.RFC3339),
				SessionIndex: params.SessionIndex,
				AuthnContext: AuthnContext{
					AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
			AttributeStatement: AttributeStatement{
				Attributes: attrs,
			},
		},
	}

	return resp, nil
}

// signEnveloped applies an enveloped XML-DSIG signature (RSA-SHA256, exclusive
// C14N) to a single element, returning the signed copy. The element's ID
// attribute drives the Reference URI. Matches OneLogin php-saml / SimpleSAMLphp
// / Keycloak / Auth0 default output; the public cert is embedded in KeyInfo so
// SPs that pinned a fingerprint can verify offline.
func signEnveloped(el *etree.Element, key *rsa.PrivateKey, certDER []byte) (*etree.Element, error) {
	keystore := &fixedKeyStore{key: key, certDER: certDER}
	signingCtx := dsig.NewDefaultSigningContext(keystore)
	signingCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, fmt.Errorf("set signature method: %w", err)
	}
	return signingCtx.SignEnveloped(el)
}

// applySignatures signs the Assertion and/or the Response per opts. The
// Assertion is signed FIRST so the Response signature (which envelopes it)
// covers the already-signed Assertion — signing the Response first then
// touching the Assertion would invalidate the Response signature.
//
// The signature is left where goxmldsig places it (enveloped, as the signed
// element's last child). onelogin/php-saml & xmlseclibs (Nextcloud, BookStack)
// locate the Signature node by reference, not by schema position, so this
// validates cleanly; repositioning it breaks goxmldsig's own round-trip.
func applySignatures(xmlBytes []byte, opts *SignOptions) ([]byte, error) {
	certDER, err := pemCertBytes(opts.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("decode signing cert: %w", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse response xml: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("empty xml document")
	}

	if opts.SignAssertion {
		assertion := root.SelectElement("Assertion")
		if assertion == nil {
			return nil, fmt.Errorf("no Assertion element to sign")
		}
		signed, err := signEnveloped(assertion, opts.Key, certDER)
		if err != nil {
			return nil, fmt.Errorf("sign assertion: %w", err)
		}
		// Assertion is the Response's last child; remove + re-append keeps it
		// in place, now carrying its own signature.
		root.RemoveChild(assertion)
		root.AddChild(signed)
	}

	if opts.SignResponse {
		signed, err := signEnveloped(root, opts.Key, certDER)
		if err != nil {
			return nil, fmt.Errorf("sign response: %w", err)
		}
		doc.SetRoot(signed)
	}

	return doc.WriteToBytes()
}

// fixedKeyStore is a minimal X509KeyStore implementation for goxmldsig
// returning a pre-built keypair. Goxmldsig's built-in MemoryX509KeyStore
// requires PEM strings; this skips one parse round-trip since the app's
// cert is already decoded by the caller.
type fixedKeyStore struct {
	key     *rsa.PrivateKey
	certDER []byte
}

func (s *fixedKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return s.key, s.certDER, nil
}

// Ensure interface compliance — goxmldsig only requires GetKeyPair.
var _ dsig.X509KeyStore = (*fixedKeyStore)(nil)

// pemCertBytes extracts the DER bytes from a PEM-encoded CERTIFICATE
// block. Accepts a raw base64 blob too (no BEGIN/END armor) for the case
// where an operator pasted just the metadata value.
func pemCertBytes(certPEM string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		return block.Bytes, nil
	}
	// Strip whitespace and re-attempt as raw base64.
	clean := bytes.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		}
		return r
	}, []byte(certPEM))
	der, err := base64.StdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil, fmt.Errorf("not a PEM certificate and not base64: %w", err)
	}
	return der, nil
}


// SignOptions controls SAML Response signing at encode time. Pass a zero
// value to skip signing — that path is for legacy SPs that explicitly
// opted out via metadata WantAssertionsSigned=false and unset Want
// MessagesSigned. Every modern SP (BookStack, Nextcloud user_saml,
// SimpleSAMLphp, Auth0 SP) expects a signed Response by default.
type SignOptions struct {
	Key           *rsa.PrivateKey
	CertPEM       string
	SignResponse  bool
	SignAssertion bool
}

// EncodeResponse base64-encodes the SAML response for POST binding.
// When sign is non-zero, applies an enveloped XML-DSIG signature first.
func EncodeResponse(resp *Response, sign *SignOptions) (string, error) {
	xmlBytes, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal response: %w", err)
	}

	// Sign before encoding. Signing must run on the canonical XML, so the
	// xmlns:xsi injection happens above it — goxmldsig parses the bytes
	// into an etree document, finds the Response element, computes the
	// digest, and writes back a Signature element inside Response.
	if sign != nil && sign.Key != nil && sign.CertPEM != "" && (sign.SignAssertion || sign.SignResponse) {
		signed, serr := applySignatures(xmlBytes, sign)
		if serr != nil {
			return "", fmt.Errorf("sign saml: %w", serr)
		}
		xmlBytes = signed
	}

	// Prepend XML declaration (only when signing didn't already add one).
	full := xmlBytes
	if !bytes.HasPrefix(full, []byte("<?xml")) {
		full = append([]byte(xml.Header), full...)
	}
	return base64.StdEncoding.EncodeToString(full), nil
}

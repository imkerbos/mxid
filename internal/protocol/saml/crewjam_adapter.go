package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	crewjam "github.com/crewjam/saml"
)

func encodeCertB64(der []byte) string { return base64.StdEncoding.EncodeToString(der) }

// This file bridges MXID's per-app SAML config + user identity into the
// crewjam/saml IdP types, so the library handles assertion/response building,
// signing, encryption, canonicalisation, and metadata — the spec edge cases the
// hand-rolled implementation got wrong (assertion signing, element order, …).

// spEntityDescriptor builds the Service Provider metadata crewjam needs to
// target a Response: ACS endpoint, entity ID, whether assertions must be signed,
// and (optionally) the SP certificate for signed-request verification /
// assertion encryption.
func spEntityDescriptor(cfg *SAMLConfig) (*crewjam.EntityDescriptor, error) {
	wantSigned := cfg.SignAssertions
	sp := &crewjam.SPSSODescriptor{
		WantAssertionsSigned: &wantSigned,
		AssertionConsumerServices: []crewjam.IndexedEndpoint{{
			Binding:  crewjam.HTTPPostBinding,
			Location: cfg.ACSURL,
			Index:    0,
		}},
	}
	if cfg.SLOURL != "" {
		sp.SingleLogoutServices = []crewjam.Endpoint{{
			Binding:  crewjam.HTTPRedirectBinding,
			Location: cfg.SLOURL,
		}}
	}

	// Optional SP certificate — enables verifying signed AuthnRequests and, in
	// future, encrypting the assertion to the SP.
	if cfg.SPCert != "" {
		certDER, err := pemCertBytes(cfg.SPCert)
		if err != nil {
			return nil, err
		}
		b64 := encodeCertB64(certDER)
		for _, use := range []string{"signing", "encryption"} {
			sp.KeyDescriptors = append(sp.KeyDescriptors, crewjam.KeyDescriptor{
				Use: use,
				KeyInfo: crewjam.KeyInfo{
					X509Data: crewjam.X509Data{
						X509Certificates: []crewjam.X509Certificate{{Data: b64}},
					},
				},
			})
		}
	}

	return &crewjam.EntityDescriptor{
		EntityID:         cfg.SPEntityID,
		SPSSODescriptors: []crewjam.SPSSODescriptor{*sp},
	}, nil
}

// staticSPProvider returns one fixed SP for the app being served — MXID resolves
// the app from the route, so there is exactly one SP per IdP instance.
type staticSPProvider struct {
	sp *crewjam.EntityDescriptor
}

func (p staticSPProvider) GetServiceProvider(_ *http.Request, _ string) (*crewjam.EntityDescriptor, error) {
	return p.sp, nil
}

// buildIdentityProvider constructs a crewjam IdP for one app/request. urls carry
// the per-request-host issuer + SSO/SLO locations; key/cert are the app's active
// signing material.
// requireAbsoluteURL parses raw and rejects anything that is not an absolute
// http(s) URL (empty, relative, or scheme-less). Returns a clear error naming
// the field so a misconfigured external URL fails loud at IdP construction
// instead of silently emitting a broken relative endpoint.
func requireAbsoluteURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: parse %q: %w", field, raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s: must be an absolute http(s) URL, got %q (external URL likely unconfigured)", field, raw)
	}
	return u, nil
}

func buildIdentityProvider(cfg *SAMLConfig, key *rsa.PrivateKey, cert *x509.Certificate, issuer, ssoURL, sloURL string) (*crewjam.IdentityProvider, error) {
	sp, err := spEntityDescriptor(cfg)
	if err != nil {
		return nil, err
	}
	// Fail loud on a non-absolute issuer/SSO URL. url.Parse accepts "" and
	// "/relative" without error, so a missing issuer (unconfigured external URL
	// in dev, or a runtime resolver returning empty) would otherwise be baked
	// SILENTLY into IdP metadata + SSO responses as a broken relative URL that
	// no SP can consume. An absolute http(s) URL is a hard precondition here.
	metaURL, err := requireAbsoluteURL("saml issuer/entityID", issuer)
	if err != nil {
		return nil, err
	}
	ssoU, err := requireAbsoluteURL("saml SSO URL", ssoURL)
	if err != nil {
		return nil, err
	}
	idp := &crewjam.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *metaURL,
		SSOURL:                  *ssoU,
		ServiceProviderProvider: staticSPProvider{sp: sp},
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}
	if sloURL != "" {
		if u, err := url.Parse(sloURL); err == nil {
			idp.LogoutURL = *u
		}
	}
	return idp, nil
}

// attrsToCrewjam converts MXID's resolved attribute map (already keyed by the
// SP-facing SAML attribute names) into crewjam Attributes.
func attrsToCrewjam(attrs map[string]string) []crewjam.Attribute {
	out := make([]crewjam.Attribute, 0, len(attrs))
	for name, val := range attrs {
		if val == "" {
			continue
		}
		out = append(out, crewjam.Attribute{
			Name:       name,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			// Type MUST be set — an empty xsi:type="" is schema-invalid and
			// strict SPs (BookStack / onelogin php-saml) reject the whole
			// Response against saml-schema-protocol-2.0.xsd.
			Values: []crewjam.AttributeValue{{Type: "xs:string", Value: val}},
		})
	}
	return out
}

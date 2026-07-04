package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
)

// rsaSHA256SigAlg is the HTTP-Redirect binding SigAlg URI for RSA-SHA256.
const rsaSHA256SigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// randomHex returns n random bytes as a hex string, for SAML message IDs.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// parseRawRedirectParam returns the raw, still-percent-encoded value of key from
// a redirect-binding query string, preserving the exact bytes the SP signed.
// url.ParseQuery would percent-decode (and reorder) the value, breaking the
// byte-for-byte signature recomputation, so we scan the raw pairs instead.
func parseRawRedirectParam(rawQuery, key string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		if eq := strings.IndexByte(pair, '='); eq >= 0 && pair[:eq] == key {
			return pair[eq+1:], true
		}
	}
	return "", false
}

// rsaPublicKeyFromCertPEM parses a PEM X.509 certificate and returns its RSA
// public key.
func rsaPublicKeyFromCertPEM(certPEM string) (*rsa.PublicKey, error) {
	der, err := pemCertBytes(certPEM)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse SP cert: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("SP cert public key is not RSA")
	}
	return pub, nil
}

// verifyRedirectSignature authenticates an incoming HTTP-Redirect binding SAML
// message (an SP-initiated LogoutRequest) against the SP's configured signing
// certificate. Per SAML bindings §3.4.4.1 the SP signs the octet string
// {SAMLRequest, RelayState?, SigAlg} in that canonical order using the exact
// percent-encoding it transmitted, so the signed string is reconstructed from
// the raw query pairs (not url.ParseQuery, which would decode/reorder them).
// Only RSA-SHA256 is accepted — the single SigAlg this IdP advertises and signs.
func verifyRedirectSignature(rawQuery, certPEM string) error {
	sigRaw, ok := parseRawRedirectParam(rawQuery, "Signature")
	if !ok {
		return fmt.Errorf("missing Signature")
	}
	sigB64, err := url.QueryUnescape(sigRaw)
	if err != nil {
		return fmt.Errorf("decode Signature: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("base64 Signature: %w", err)
	}

	sigAlgRaw, ok := parseRawRedirectParam(rawQuery, "SigAlg")
	if !ok {
		return fmt.Errorf("missing SigAlg")
	}
	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return fmt.Errorf("decode SigAlg: %w", err)
	}
	if sigAlg != rsaSHA256SigAlg {
		return fmt.Errorf("unsupported SigAlg %q", sigAlg)
	}

	reqRaw, ok := parseRawRedirectParam(rawQuery, "SAMLRequest")
	if !ok {
		return fmt.Errorf("missing SAMLRequest")
	}
	// Canonical signed order: SAMLRequest, RelayState (if sent), SigAlg.
	signed := "SAMLRequest=" + reqRaw
	if rsRaw, ok := parseRawRedirectParam(rawQuery, "RelayState"); ok {
		signed += "&RelayState=" + rsRaw
	}
	signed += "&SigAlg=" + sigAlgRaw

	pub, err := rsaPublicKeyFromCertPEM(certPEM)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(signed))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
}

// buildLogoutResponseRedirect assembles a SAML LogoutResponse for an SP-initiated
// SLO and returns the SP SLS URL carrying the HTTP-Redirect binding query
// (SAMLResponse + RelayState + SigAlg + Signature).
//
// crewjam/saml has no IdP-side SLO helper (it only models the SP side), so we
// build the LogoutResponse from its schema type by hand. Per the redirect
// binding (SAML bindings §3.4.4.1) the signature covers the URL-encoded query
// octet string — NOT an enveloped XML signature — so the response XML itself is
// sent unsigned/deflated and the RSA-SHA256 signature is appended as a query
// param. This is why no goxmldsig is needed here.
func buildLogoutResponseRedirect(destination, issuer, inResponseTo, relayState string, key *rsa.PrivateKey) (string, error) {
	resp := crewjam.LogoutResponse{
		ID:           fmt.Sprintf("id-%s", randomHex(20)),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  destination,
		Issuer: &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Status: crewjam.Status{
			StatusCode: crewjam.StatusCode{Value: crewjam.StatusSuccess},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("marshal LogoutResponse: %w", err)
	}

	q, err := signRedirectQuery("SAMLResponse", xmlBytes, relayState, key)
	if err != nil {
		return "", err
	}

	sep := "?"
	if strings.Contains(destination, "?") {
		sep = "&"
	}
	return destination + sep + q, nil
}

// deflateBase64 applies the HTTP-Redirect binding payload encoding: raw DEFLATE
// (no zlib header) followed by standard base64. Shared by the LogoutResponse and
// LogoutRequest redirect builders.
func deflateBase64(xmlBytes []byte) (string, error) {
	var deflated bytes.Buffer
	fw, _ := flate.NewWriter(&deflated, flate.DefaultCompression)
	if _, err := fw.Write(xmlBytes); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(deflated.Bytes()), nil
}

// signRedirectQuery builds the signed HTTP-Redirect binding query string for a
// SAML message. paramName is "SAMLResponse" (IdP answering an SP) or
// "SAMLRequest" (IdP-initiated LogoutRequest). Per SAML bindings §3.4.4.1 the
// RSA-SHA256 signature covers the URL-encoded octet string {paramName,
// RelayState?, SigAlg} in that exact order — NOT an enveloped XML signature — so
// the SP can recompute it byte-for-byte. The returned query already includes the
// trailing Signature param.
func signRedirectQuery(paramName string, xmlBytes []byte, relayState string, key *rsa.PrivateKey) (string, error) {
	encoded, err := deflateBase64(xmlBytes)
	if err != nil {
		return "", err
	}

	q := paramName + "=" + url.QueryEscape(encoded)
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(rsaSHA256SigAlg)

	sum := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign %s: %w", paramName, err)
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return q, nil
}

// buildLogoutRequestRedirect assembles an IdP-initiated SAML LogoutRequest and
// returns the SP SLO URL carrying the HTTP-Redirect binding query (SAMLRequest +
// SigAlg + Signature). It addresses one specific SP session via NameID +
// SessionIndex (captured at SSO time and stored in the SessionIndexStore).
//
// crewjam/saml models only the SP side of SLO, so — as with the LogoutResponse
// builder above — the LogoutRequest XML is hand-built from its schema type and
// signed via the redirect-binding query signature rather than an enveloped XML
// signature.
func buildLogoutRequestRedirect(destination, issuer, nameID, nameIDFormat, sessionIndex string, key *rsa.PrivateKey) (string, error) {
	if nameIDFormat == "" {
		nameIDFormat = NameIDEmail
	}
	req := crewjam.LogoutRequest{
		ID:           fmt.Sprintf("id-%s", randomHex(20)),
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  destination,
		Issuer: &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		NameID: &crewjam.NameID{
			Format: nameIDFormat,
			Value:  nameID,
		},
		SessionIndex: &crewjam.SessionIndex{Value: sessionIndex},
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("marshal LogoutRequest: %w", err)
	}

	q, err := signRedirectQuery("SAMLRequest", xmlBytes, "", key)
	if err != nil {
		return "", err
	}

	sep := "?"
	if strings.Contains(destination, "?") {
		sep = "&"
	}
	return destination + sep + q, nil
}

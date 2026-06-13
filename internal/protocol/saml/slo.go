package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

	// DEFLATE (raw, no zlib header) + base64 — HTTP-Redirect binding.
	var deflated bytes.Buffer
	fw, _ := flate.NewWriter(&deflated, flate.DefaultCompression)
	if _, err := fw.Write(xmlBytes); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	samlResponse := base64.StdEncoding.EncodeToString(deflated.Bytes())

	// Octet string to sign, in the exact order the binding mandates:
	// SAMLResponse, RelayState (if present), SigAlg — each individually
	// URL-encoded. The SP recomputes this string to verify, so order and
	// encoding must match byte-for-byte.
	q := "SAMLResponse=" + url.QueryEscape(samlResponse)
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(rsaSHA256SigAlg)

	sum := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign LogoutResponse: %w", err)
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))

	sep := "?"
	if strings.Contains(destination, "?") {
		sep = "&"
	}
	return destination + sep + q, nil
}

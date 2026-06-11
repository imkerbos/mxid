// Round-trip test for SAML Response signing.
//
// Verifies that EncodeResponse produces a Response with a valid enveloped
// XML-DSIG signature that goxmldsig itself can validate end-to-end. Catches
// canonicalisation drift, certificate embedding mistakes, and signature
// algorithm mismatches before they hit a real SP (BookStack / Nextcloud /
// SimpleSAMLphp) where the only feedback is "No Signature found" or
// "Signature validation failed".
package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	dsig "github.com/russellhaering/goxmldsig"
)

// newTestKeyPair mints a self-signed X.509 + RSA-2048 keypair on the fly
// so the test is hermetic (no fixtures, no master-key dependency).
func newTestKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mxid-saml-test"},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return key, string(certPEM)
}

func TestEncodeResponse_SignedAndVerifiable(t *testing.T) {
	key, certPEM := newTestKeyPair(t)
	builder := NewAssertionBuilder("http://192.168.254.200:3500")
	resp, err := builder.BuildResponse(&BuildParams{
		RequestID:    "ONELOGIN_test_request_id",
		ACSURL:       "http://192.168.254.200:4005/saml2/acs",
		SPEntityID:   "http://192.168.254.200:4005/saml2/metadata",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDValue:  "admin@example.com",
		User: &resolver.IdentityInfo{
			ID:       1,
			Username: "admin",
			Email:    "admin@example.com",
		},
		Attributes: map[string]string{
			"username":    "admin",
			"email":       "admin@example.com",
			"displayname": "Administrator",
		},
		TTL:    8 * time.Hour,
		Issuer: "http://192.168.254.200:3500",
	})
	if err != nil {
		t.Fatalf("BuildResponse: %v", err)
	}

	encoded, err := EncodeResponse(resp, &SignOptions{Key: key, CertPEM: certPEM})
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// 1. Structural assertions.
	xmlStr := string(xmlBytes)
	for _, want := range []string{
		`<ds:Signature`,
		`<ds:SignedInfo`,
		`<ds:SignatureValue`,
		`<ds:X509Certificate`,
		"InResponseTo=\"ONELOGIN_test_request_id\"",
	} {
		if !strings.Contains(xmlStr, want) {
			t.Errorf("signed Response missing %q. Got:\n%s", want, xmlStr)
		}
	}

	// 2. Verify the signature with goxmldsig itself — round-trip check.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("re-parse signed xml: %v", err)
	}
	root := doc.Root()
	if root == nil {
		t.Fatalf("no root element in signed xml")
	}

	keyStore := &fixedKeyStore{key: key, certDER: mustCertDER(t, certPEM)}
	vctx := dsig.NewDefaultValidationContext(&trustingStore{store: keyStore})
	if _, err := vctx.Validate(root); err != nil {
		t.Fatalf("dsig validation failed: %v\nXML:\n%s", err, xmlStr)
	}

	// 3. Quick sanity: dump signed XML on -v so operators can eyeball it.
	t.Logf("signed Response XML:\n%s", xmlStr)
}

// trustingStore wraps fixedKeyStore so it implements the
// X509CertificateStore interface that goxmldsig's validation context
// expects (returning the certificate as a trust anchor).
type trustingStore struct {
	store *fixedKeyStore
}

func (t *trustingStore) Certificates() ([]*x509.Certificate, error) {
	c, err := x509.ParseCertificate(t.store.certDER)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{c}, nil
}

func mustCertDER(t *testing.T, certPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("bad test PEM")
	}
	return block.Bytes
}

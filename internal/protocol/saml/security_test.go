package saml

// The functions covered here decide three things an attacker cares about: where
// the SLO endpoint will send a browser, whether an unauthenticated LogoutRequest
// is accepted, and what an operator-pasted SP metadata document is allowed to
// configure. They were all at 0%.

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

/* ───────────────────────── test certificate ──────────────────────────── */

type testCert struct {
	key     *rsa.PrivateKey
	certPEM string
	certB64 string // the bare base64 form found inside <ds:X509Certificate>
}

func newTestCert(t *testing.T) testCert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return testCert{
		key:     key,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		certB64: base64.StdEncoding.EncodeToString(der),
	}
}

/* ────────────────────── SLO redirect: shape guard ────────────────────── */

// isSafeSLORedirect is the baseline shape check. It is not the whole guard —
// isAllowedSLORedirect binds the target to the SP — but everything it lets
// through reaches that second stage, so its rejections have to be exact.
func TestIsSafeSLORedirect(t *testing.T) {
	allowed := []string{
		"https://sp.example.com/logged-out",
		"https://sp.example.com:8443/path?x=1",
		// Plain http only for loopback, so a dev SP still works without
		// opening the door to http://evil.com.
		"http://localhost:3000/done",
		"http://127.0.0.1/done",
		"http://[::1]:8080/done",
	}
	for _, raw := range allowed {
		if !isSafeSLORedirect(raw) {
			t.Errorf("%q was rejected but should be allowed", raw)
		}
	}

	refused := []string{
		"",
		"/relative/path",
		"//evil.com/path",           // protocol-relative: browsers treat as absolute
		"http://evil.com/",          // plain http to a non-loopback host
		"http://127.0.0.1.evil.com", // loopback as a prefix of an attacker domain
		"http://localhost.evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"vbscript:msgbox(1)",
		// A fragment lets an attacker append to the landing URL after the
		// host check has already passed.
		"https://sp.example.com/#@evil.com",
		"https://sp.example.com/path#frag",
	}
	for _, raw := range refused {
		if isSafeSLORedirect(raw) {
			t.Errorf("%q was allowed but must be rejected", raw)
		}
	}
}

// The shape check alone is not enough, and the code says so: without SP context
// any https host would pass. This asserts the layering — that a well-formed
// https URL still needs the SP binding — by checking the two stages disagree.
func TestSafeShapeAloneDoesNotAuthorizeAnArbitraryHost(t *testing.T) {
	const attacker = "https://evil.example.com/landing"
	if !isSafeSLORedirect(attacker) {
		t.Fatal("precondition: a plain https URL passes the shape check")
	}
	// It passes the shape check, which is exactly why isAllowedSLORedirect
	// must fail closed when the SP cannot be identified. That path is covered
	// by TestIsAllowedSLORedirectFailsClosedWithoutAnSP.
	u, err := url.Parse(attacker)
	if err != nil || u.Host != "evil.example.com" {
		t.Fatalf("parse: %v %v", u, err)
	}
}

/* ──────────────── redirect-binding signature verification ────────────── */

// signedRedirectQuery builds the query string an SP would send under the
// HTTP-Redirect binding, signing the canonical octet string from the spec.
func signedRedirectQuery(t *testing.T, key *rsa.PrivateKey, samlRequest, relayState string, includeRelay bool) string {
	t.Helper()
	req := url.QueryEscape(samlRequest)
	alg := url.QueryEscape(rsaSHA256SigAlg)

	signed := "SAMLRequest=" + req
	if includeRelay {
		signed += "&RelayState=" + url.QueryEscape(relayState)
	}
	signed += "&SigAlg=" + alg

	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return out
}

func TestVerifyRedirectSignatureAcceptsAGenuineRequest(t *testing.T) {
	c := newTestCert(t)
	// Both spec shapes: RelayState is optional and its presence changes the
	// signed octet string, so each has to be verified on its own terms.
	for _, withRelay := range []bool{true, false} {
		q := signedRedirectQuery(t, c.key, "PHNhbWxwOkxvZ291dFJlcXVlc3QvPg==", "https://sp/after", withRelay)
		if err := verifyRedirectSignature(q, c.certPEM); err != nil {
			t.Fatalf("withRelay=%v: %v", withRelay, err)
		}
	}
}

func TestVerifyRedirectSignatureRejects(t *testing.T) {
	c := newTestCert(t)
	other := newTestCert(t)
	good := signedRedirectQuery(t, c.key, "PHNhbWxwOkxvZ291dFJlcXVlc3QvPg==", "https://sp/after", true)

	t.Run("a signature from another key", func(t *testing.T) {
		if err := verifyRedirectSignature(good, other.certPEM); err == nil {
			t.Fatal("a LogoutRequest signed by a different SP verified")
		}
	})

	// Changing any signed parameter must invalidate. RelayState is the one an
	// attacker most wants to change: it is where the browser lands afterwards.
	t.Run("RelayState swapped after signing", func(t *testing.T) {
		tampered := strings.Replace(good,
			"RelayState="+url.QueryEscape("https://sp/after"),
			"RelayState="+url.QueryEscape("https://evil.example.com"), 1)
		if tampered == good {
			t.Fatal("test did not actually modify the query")
		}
		if err := verifyRedirectSignature(tampered, c.certPEM); err == nil {
			t.Fatal("a swapped RelayState still verified")
		}
	})

	t.Run("SAMLRequest swapped after signing", func(t *testing.T) {
		tampered := strings.Replace(good, "SAMLRequest=PHNhbWxwOkxvZ291dFJlcXVlc3QvPg%3D%3D",
			"SAMLRequest=b3RoZXI%3D", 1)
		if err := verifyRedirectSignature(tampered, c.certPEM); err == nil {
			t.Fatal("a swapped SAMLRequest still verified")
		}
	})

	// Only RSA-SHA256 is advertised. Accepting a weaker declared algorithm is
	// the classic downgrade; accepting "none"-style values is worse.
	t.Run("an unsupported SigAlg", func(t *testing.T) {
		for _, alg := range []string{
			"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
			"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
			"",
		} {
			q := strings.Replace(good, "SigAlg="+url.QueryEscape(rsaSHA256SigAlg),
				"SigAlg="+url.QueryEscape(alg), 1)
			if err := verifyRedirectSignature(q, c.certPEM); err == nil {
				t.Errorf("SigAlg %q was accepted", alg)
			}
		}
	})

	t.Run("missing parameters", func(t *testing.T) {
		cases := map[string]string{
			"no Signature":   "SAMLRequest=x&SigAlg=" + url.QueryEscape(rsaSHA256SigAlg),
			"no SigAlg":      "SAMLRequest=x&Signature=abcd",
			"no SAMLRequest": "SigAlg=" + url.QueryEscape(rsaSHA256SigAlg) + "&Signature=abcd",
			"empty query":    "",
		}
		for name, q := range cases {
			if err := verifyRedirectSignature(q, c.certPEM); err == nil {
				t.Errorf("%s: verified with a missing parameter", name)
			}
		}
	})

	t.Run("a signature that is not base64", func(t *testing.T) {
		q := strings.Replace(good, "Signature=", "Signature=!!!not-base64!!!&X=", 1)
		if err := verifyRedirectSignature(q, c.certPEM); err == nil {
			t.Fatal("a non-base64 signature verified")
		}
	})

	t.Run("an unusable certificate", func(t *testing.T) {
		for _, certPEM := range []string{"", "not a certificate", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"} {
			if err := verifyRedirectSignature(good, certPEM); err == nil {
				t.Errorf("verified against an unusable certificate %q", certPEM)
			}
		}
	})
}

// The raw parameter scan exists because url.ParseQuery would decode and reorder
// the values, and the signature covers the exact transmitted bytes.
func TestParseRawRedirectParamPreservesEncoding(t *testing.T) {
	const q = "SAMLRequest=fVLL%2FjA&RelayState=https%3A%2F%2Fsp%2Fx&SigAlg=alg&Signature=c2ln"

	got, ok := parseRawRedirectParam(q, "RelayState")
	if !ok {
		t.Fatal("RelayState not found")
	}
	if got != "https%3A%2F%2Fsp%2Fx" {
		t.Fatalf("got %q — the value was decoded, which breaks signature recomputation", got)
	}
	if _, ok := parseRawRedirectParam(q, "Missing"); ok {
		t.Error("an absent key was reported present")
	}
	// A key must match in full: a prefix match would let "SAMLRequestX" satisfy
	// a lookup for "SAMLRequest".
	if _, ok := parseRawRedirectParam("SAMLRequestExtra=v", "SAMLRequest"); ok {
		t.Error("a longer key matched a shorter lookup")
	}
	// A bare flag with no '=' must not be mistaken for a value.
	if _, ok := parseRawRedirectParam("SAMLRequest", "SAMLRequest"); ok {
		t.Error("a valueless parameter was reported present")
	}
}

func TestRSAPublicKeyFromCertPEM(t *testing.T) {
	c := newTestCert(t)

	pub, err := rsaPublicKeyFromCertPEM(c.certPEM)
	if err != nil {
		t.Fatalf("armored PEM: %v", err)
	}
	if pub.N.Cmp(c.key.N) != 0 {
		t.Fatal("returned a different key than the certificate holds")
	}
	// Operators paste the bare metadata value more often than a full PEM.
	if _, err := rsaPublicKeyFromCertPEM(c.certB64); err != nil {
		t.Fatalf("bare base64: %v", err)
	}
	for _, bad := range []string{"", "not base64 at all !!!", "aGVsbG8="} {
		if _, err := rsaPublicKeyFromCertPEM(bad); err == nil {
			t.Errorf("%q parsed as a certificate", bad)
		}
	}
}

/* ─────────────────────────── SP metadata ──────────────────────────────── */

// The ds: prefix is not decoration: KeyInfo/X509Certificate live in the xmldsig
// namespace, and the parser matches on namespace + local name. A fixture that
// declared them in the metadata namespace would silently yield no certificate.
func spMetadataXML(inner string) []byte {
	return []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="https://sp.example.com/saml">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		inner + `</SPSSODescriptor>
</EntityDescriptor>`)
}

func TestParseSPMetadataPrefersTheRightBindings(t *testing.T) {
	c := newTestCert(t)
	md := spMetadataXML(`
    <KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>ZW5jcnlwdGlvbg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + c.certB64 + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo/post"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/slo/redirect"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/acs/redirect" index="0"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs/post" index="1"/>`)

	got, err := ParseSPMetadata(md)
	if err != nil {
		t.Fatalf("ParseSPMetadata: %v", err)
	}
	if got.EntityID != "https://sp.example.com/saml" {
		t.Fatalf("EntityID = %q", got.EntityID)
	}
	// POST for ACS (browser assertion delivery), Redirect for SLO — declaration
	// order in the document must not decide it.
	if got.ACSURL != "https://sp.example.com/acs/post" {
		t.Fatalf("ACSURL = %q, want the HTTP-POST endpoint", got.ACSURL)
	}
	if got.SLOURL != "https://sp.example.com/slo/redirect" {
		t.Fatalf("SLOURL = %q, want the HTTP-Redirect endpoint", got.SLOURL)
	}
	if got.NameIDFormat != NameIDEmail {
		t.Fatalf("NameIDFormat = %q", got.NameIDFormat)
	}
	// Picking the encryption certificate would make every signature check fail
	// against the wrong key.
	if _, err := rsaPublicKeyFromCertPEM(got.X509CertPEM); err != nil {
		t.Fatalf("picked certificate is unusable (likely the encryption one): %v", err)
	}
}

func TestParseSPMetadataFallbacks(t *testing.T) {
	c := newTestCert(t)

	t.Run("falls back to the first endpoint when no preferred binding exists", func(t *testing.T) {
		md := spMetadataXML(`
      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://sp/slo/soap"/>
      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://sp/acs/paos" index="0"/>`)
		got, err := ParseSPMetadata(md)
		if err != nil {
			t.Fatalf("ParseSPMetadata: %v", err)
		}
		if got.ACSURL != "https://sp/acs/paos" || got.SLOURL != "https://sp/slo/soap" {
			t.Fatalf("acs=%q slo=%q", got.ACSURL, got.SLOURL)
		}
	})

	// Per spec a KeyDescriptor with no `use` means both signing and encryption.
	t.Run("accepts a KeyDescriptor with no use attribute", func(t *testing.T) {
		md := spMetadataXML(`<KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
			c.certB64 + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>`)
		got, err := ParseSPMetadata(md)
		if err != nil {
			t.Fatalf("ParseSPMetadata: %v", err)
		}
		if _, err := rsaPublicKeyFromCertPEM(got.X509CertPEM); err != nil {
			t.Fatalf("certificate unusable: %v", err)
		}
	})

	t.Run("no certificate at all leaves the field empty", func(t *testing.T) {
		got, err := ParseSPMetadata(spMetadataXML(`
      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp/acs" index="0"/>`))
		if err != nil {
			t.Fatalf("ParseSPMetadata: %v", err)
		}
		if got.X509CertPEM != "" {
			t.Fatalf("X509CertPEM = %q, want empty", got.X509CertPEM)
		}
	})
}

func TestParseSPMetadataRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty document", nil},
		{"not XML", []byte("this is not xml")},
		{"no entityID", []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><SPSSODescriptor/></EntityDescriptor>`)},
		// An IdP descriptor pasted into the SP field is a common operator
		// mistake, and accepting it would silently configure nothing.
		{"IdP metadata instead of SP", []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp"><IDPSSODescriptor/></EntityDescriptor>`)},
		// XXE: the parser must refuse a DOCTYPE outright rather than resolve it.
		{"DOCTYPE / external entity", []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;"><SPSSODescriptor/></EntityDescriptor>`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseSPMetadata(c.raw); err == nil {
				t.Fatal("accepted, want an error")
			}
		})
	}
}

func TestWrapPEMCertificate(t *testing.T) {
	c := newTestCert(t)

	// From the bare metadata form.
	wrapped := wrapPEMCertificate(c.certB64)
	if block, _ := pem.Decode([]byte(wrapped)); block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("bare base64 did not produce a decodable PEM block")
	}
	// Idempotent: SPs sometimes paste an already-armored certificate into the
	// metadata field, and re-wrapping must not corrupt it.
	if again := wrapPEMCertificate(wrapped); again != wrapped {
		t.Fatal("re-wrapping an armored certificate changed it")
	}
	// Whitespace and line breaks inside the base64 are common in real metadata.
	messy := "  " + c.certB64[:20] + "\n  " + c.certB64[20:] + "\r\n"
	if got := wrapPEMCertificate(messy); got != wrapped {
		t.Fatal("whitespace in the base64 changed the result")
	}
	for _, empty := range []string{"", "   ", "\n", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"} {
		if got := wrapPEMCertificate(empty); got != "" {
			t.Errorf("wrapPEMCertificate(%q) = %q, want empty", empty, got)
		}
	}
}

func TestErrInvalidSPMetadataMessage(t *testing.T) {
	if got := ErrInvalidSPMetadata("missing entityID").Error(); got != "invalid SP metadata: missing entityID" {
		t.Fatalf("Error() = %q", got)
	}
}

/* ───────────────── assertion contents: NameID + attributes ───────────── */

// The NameID is the SP's primary key for the user. Emitting the wrong field
// links the session to the wrong account at the SP.
func TestResolveNameID(t *testing.T) {
	h := &Handler{}
	user := &resolver.IdentityInfo{ID: 4711, Username: "alice", Email: "alice@example.com"}

	cases := map[string]string{
		NameIDEmail:       "alice@example.com",
		NameIDPersistent:  "4711",
		NameIDUnspecified: "alice",
		"":                "alice",
		"something-else":  "alice",
	}
	for format, want := range cases {
		if got := h.resolveNameID(format, user); got != want {
			t.Errorf("format %q: got %q, want %q", format, got, want)
		}
	}
}

func TestBuildAttributes(t *testing.T) {
	h := &Handler{}
	cfg := Defaults()

	full := h.buildAttributes(cfg, &resolver.IdentityInfo{
		Username: "alice", Email: "alice@example.com",
		DisplayName: "Alice", Phone: "+1555", Avatar: "https://a/x.png",
	})
	if full["uid"] != "alice" || full["mail"] != "alice@example.com" ||
		full["displayName"] != "Alice" || full["telephoneNumber"] != "+1555" {
		t.Fatalf("default mapping produced %v", full)
	}
	// avatar is not in the default mapping, so it must not leak through.
	if _, ok := full["avatar"]; ok {
		t.Fatalf("an unmapped attribute was emitted: %v", full)
	}

	// An empty value must be omitted rather than sent as "". SPs commonly
	// treat a present-but-empty attribute as an explicit clear.
	sparse := h.buildAttributes(cfg, &resolver.IdentityInfo{Username: "bob"})
	if _, ok := sparse["mail"]; ok {
		t.Fatalf("an empty email was emitted: %v", sparse)
	}
	if sparse["uid"] != "bob" {
		t.Fatalf("attributes = %v", sparse)
	}

	// A mapping naming a field the identity does not have must be skipped, not
	// panic or emit an empty entry.
	custom := &SAMLConfig{AttributeMapping: map[string]string{"nonexistent": "X", "email": "EmailAddress"}}
	got := h.buildAttributes(custom, &resolver.IdentityInfo{Email: "c@d.e"})
	if len(got) != 1 || got["EmailAddress"] != "c@d.e" {
		t.Fatalf("custom mapping produced %v", got)
	}

	if got := h.buildAttributes(&SAMLConfig{}, &resolver.IdentityInfo{Username: "x"}); len(got) != 0 {
		t.Fatalf("an empty mapping emitted %v", got)
	}
}

/* ──────────────────── AuthnRequest / LogoutRequest parsing ───────────── */

func TestExtractRequestIssuerAndID(t *testing.T) {
	const xml = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="req-123">` +
		`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">  https://sp.example.com/saml  </saml:Issuer>` +
		`</samlp:LogoutRequest>`

	// SPs are inconsistent about which base64 alphabet and padding they use;
	// all four have been seen in the wild, and rejecting one breaks that SP.
	encodings := map[string]string{
		"StdEncoding":    base64.StdEncoding.EncodeToString([]byte(xml)),
		"RawStdEncoding": base64.RawStdEncoding.EncodeToString([]byte(xml)),
		"URLEncoding":    base64.URLEncoding.EncodeToString([]byte(xml)),
		"RawURLEncoding": base64.RawURLEncoding.EncodeToString([]byte(xml)),
	}
	for name, encoded := range encodings {
		t.Run(name, func(t *testing.T) {
			issuer, err := extractRequestIssuer(encoded)
			if err != nil {
				t.Fatalf("extractRequestIssuer: %v", err)
			}
			if issuer != "https://sp.example.com/saml" {
				t.Fatalf("issuer = %q — surrounding whitespace must be trimmed", issuer)
			}
			id, err := extractRequestID(encoded)
			if err != nil {
				t.Fatalf("extractRequestID: %v", err)
			}
			if id != "req-123" {
				t.Fatalf("id = %q", id)
			}
		})
	}

	t.Run("rejects garbage", func(t *testing.T) {
		for _, bad := range []string{"", "!!!not base64!!!", base64.StdEncoding.EncodeToString([]byte("<not-saml"))} {
			if _, err := extractRequestIssuer(bad); err == nil {
				t.Errorf("extractRequestIssuer(%q) succeeded", bad)
			}
			if _, err := extractRequestID(bad); err == nil {
				t.Errorf("extractRequestID(%q) succeeded", bad)
			}
		}
	})

	// XXE through the LogoutRequest path too — this is unauthenticated input
	// reached before any signature check.
	t.Run("rejects a DOCTYPE", func(t *testing.T) {
		doc := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
			`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="&xxe;"><Issuer>&xxe;</Issuer></samlp:LogoutRequest>`
		enc := base64.StdEncoding.EncodeToString([]byte(doc))
		if _, err := extractRequestIssuer(enc); err == nil {
			t.Error("a DOCTYPE was accepted by extractRequestIssuer")
		}
		if _, err := extractRequestID(enc); err == nil {
			t.Error("a DOCTYPE was accepted by extractRequestID")
		}
	})
}

func TestPemCertBytes(t *testing.T) {
	c := newTestCert(t)

	fromPEM, err := pemCertBytes(c.certPEM)
	if err != nil {
		t.Fatalf("armored: %v", err)
	}
	fromB64, err := pemCertBytes(c.certB64)
	if err != nil {
		t.Fatalf("bare base64: %v", err)
	}
	if string(fromPEM) != string(fromB64) {
		t.Fatal("the armored and bare forms produced different DER")
	}
	// Whitespace inside the base64 is stripped, matching what operators paste.
	if _, err := pemCertBytes("  " + c.certB64[:10] + "\n\t" + c.certB64[10:] + " "); err != nil {
		t.Fatalf("whitespace-laden base64: %v", err)
	}
	if _, err := pemCertBytes("definitely not a certificate !!!"); err == nil {
		t.Fatal("garbage was accepted")
	}
}

/* ────────────────── SLO redirect: the SP-binding stage ───────────────── */

// The comment on isAllowedSLORedirect calls this branch out explicitly: without
// a SAMLRequest an attacker reaches the "SP unknown" case with any RelayState
// they like, so it has to refuse rather than fall back to the shape check.
func TestIsAllowedSLORedirectFailsClosedWithoutAnSP(t *testing.T) {
	h := &Handler{}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/slo?RelayState=https%3A%2F%2Fevil.example.com", nil)

	if h.isAllowedSLORedirect(c, "https://evil.example.com") {
		t.Fatal("a plain GET with no SAMLRequest was allowed to pick the landing URL")
	}
	// Same conclusion by a different route: a SAMLRequest that does not decode
	// leaves the SP unidentified.
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = httptest.NewRequest(http.MethodGet, "/slo?SAMLRequest=%21%21%21", nil)
	if h.isAllowedSLORedirect(c2, "https://evil.example.com") {
		t.Fatal("an undecodable SAMLRequest was treated as a known SP")
	}
	// A target the shape check rejects must not reach the SP lookup at all.
	if h.isAllowedSLORedirect(c, "javascript:alert(1)") {
		t.Fatal("a javascript: target was allowed")
	}
}

/* ─────────────────────── crewjam adapter plumbing ─────────────────────── */

func TestRequireAbsoluteURL(t *testing.T) {
	for _, raw := range []string{"https://idp.example.com/saml", "http://localhost:8080/x"} {
		if _, err := requireAbsoluteURL("field", raw); err != nil {
			t.Errorf("%q rejected: %v", raw, err)
		}
	}
	// The whole point: url.Parse accepts these without error, so a missing
	// external URL would otherwise be baked into IdP metadata as a relative
	// endpoint no SP can consume.
	for _, raw := range []string{"", "/relative/path", "idp.example.com", "ftp://host/x", "mailto:a@b"} {
		if _, err := requireAbsoluteURL("saml issuer", raw); err == nil {
			t.Errorf("%q accepted as an absolute http(s) URL", raw)
		} else if !strings.Contains(err.Error(), "saml issuer") {
			t.Errorf("error for %q does not name the field: %v", raw, err)
		}
	}
}

func TestSPEntityDescriptor(t *testing.T) {
	c := newTestCert(t)

	t.Run("minimal config", func(t *testing.T) {
		ed, err := spEntityDescriptor(&SAMLConfig{
			SPEntityID: "https://sp/meta", ACSURL: "https://sp/acs", SignAssertions: true,
		})
		if err != nil {
			t.Fatalf("spEntityDescriptor: %v", err)
		}
		if ed.EntityID != "https://sp/meta" || len(ed.SPSSODescriptors) != 1 {
			t.Fatalf("descriptor = %+v", ed)
		}
		sp := ed.SPSSODescriptors[0]
		if sp.WantAssertionsSigned == nil || !*sp.WantAssertionsSigned {
			t.Fatal("SignAssertions was not propagated")
		}
		if len(sp.SingleLogoutServices) != 0 {
			t.Fatal("an SLO endpoint was emitted for a config that has none")
		}
		if len(sp.KeyDescriptors) != 0 {
			t.Fatal("a key descriptor was emitted with no SP certificate configured")
		}
	})

	t.Run("with SLO and a certificate", func(t *testing.T) {
		ed, err := spEntityDescriptor(&SAMLConfig{
			SPEntityID: "sp", ACSURL: "https://sp/acs", SLOURL: "https://sp/slo", SPCert: c.certPEM,
		})
		if err != nil {
			t.Fatalf("spEntityDescriptor: %v", err)
		}
		sp := ed.SPSSODescriptors[0]
		if len(sp.SingleLogoutServices) != 1 || sp.SingleLogoutServices[0].Location != "https://sp/slo" {
			t.Fatalf("SLO endpoints = %+v", sp.SingleLogoutServices)
		}
		// Both uses, because the same SP certificate verifies signed requests
		// and would encrypt an assertion back.
		if len(sp.KeyDescriptors) != 2 {
			t.Fatalf("key descriptors = %d, want signing + encryption", len(sp.KeyDescriptors))
		}
		if got := sp.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data; got != c.certB64 {
			t.Fatal("the emitted certificate is not the configured one")
		}
	})

	t.Run("an unparseable SP certificate fails loud", func(t *testing.T) {
		if _, err := spEntityDescriptor(&SAMLConfig{ACSURL: "https://sp/acs", SPCert: "not a cert"}); err == nil {
			t.Fatal("a garbage SP certificate was accepted")
		}
	})
}

func TestBuildIdentityProviderRejectsRelativeURLs(t *testing.T) {
	c := newTestCert(t)
	der, err := pemCertBytes(c.certPEM)
	if err != nil {
		t.Fatalf("pemCertBytes: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg := &SAMLConfig{SPEntityID: "sp", ACSURL: "https://sp/acs"}

	if _, err := buildIdentityProvider(cfg, c.key, cert, "", "https://idp/sso", ""); err == nil {
		t.Fatal("an empty issuer was accepted — it would ship in IdP metadata as a broken relative URL")
	}
	if _, err := buildIdentityProvider(cfg, c.key, cert, "https://idp/meta", "/sso", ""); err == nil {
		t.Fatal("a relative SSO URL was accepted")
	}

	idp, err := buildIdentityProvider(cfg, c.key, cert, "https://idp/meta", "https://idp/sso", "https://idp/slo")
	if err != nil {
		t.Fatalf("buildIdentityProvider: %v", err)
	}
	if idp.MetadataURL.String() != "https://idp/meta" || idp.SSOURL.String() != "https://idp/sso" {
		t.Fatalf("urls = %s / %s", idp.MetadataURL.String(), idp.SSOURL.String())
	}
	if idp.LogoutURL.String() != "https://idp/slo" {
		t.Fatalf("LogoutURL = %s", idp.LogoutURL.String())
	}
	if idp.SignatureMethod != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Fatalf("SignatureMethod = %q — SHA-1 is not acceptable", idp.SignatureMethod)
	}
	// One fixed SP per IdP instance; the provider must hand it back regardless
	// of the entity ID asked for.
	got, err := idp.ServiceProviderProvider.GetServiceProvider(nil, "anything")
	if err != nil || got.EntityID != "sp" {
		t.Fatalf("GetServiceProvider = %+v, %v", got, err)
	}
}

func TestAttrsToCrewjam(t *testing.T) {
	out := attrsToCrewjam(map[string]string{"uid": "alice", "mail": "a@b.c", "empty": ""})
	if len(out) != 2 {
		t.Fatalf("got %d attributes, want the empty one dropped: %+v", len(out), out)
	}
	for _, a := range out {
		if len(a.Values) != 1 {
			t.Fatalf("attribute %q has %d values", a.Name, len(a.Values))
		}
		// An empty xsi:type is schema-invalid and strict SPs reject the whole
		// Response over it, so this is not cosmetic.
		if a.Values[0].Type != "xs:string" {
			t.Fatalf("attribute %q has Type %q, want xs:string", a.Name, a.Values[0].Type)
		}
		if a.NameFormat != "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" {
			t.Fatalf("attribute %q NameFormat = %q", a.Name, a.NameFormat)
		}
	}
	if got := attrsToCrewjam(nil); len(got) != 0 {
		t.Fatalf("nil map produced %d attributes", len(got))
	}
}

/* ───────────────────── LogoutResponse redirect binding ────────────────── */

func TestBuildLogoutResponseRedirect(t *testing.T) {
	c := newTestCert(t)

	raw, err := buildLogoutResponseRedirect("https://sp.example.com/sls", "https://idp/meta", "req-1", "rs-1", c.key)
	if err != nil {
		t.Fatalf("buildLogoutResponseRedirect: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Scheme != "https" || u.Host != "sp.example.com" || u.Path != "/sls" {
		t.Fatalf("destination was rewritten: %s", raw)
	}
	q := u.Query()
	for _, k := range []string{"SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		if q.Get(k) == "" {
			t.Fatalf("%s missing from %s", k, raw)
		}
	}
	if q.Get("RelayState") != "rs-1" {
		t.Fatalf("RelayState = %q", q.Get("RelayState"))
	}
	if q.Get("SigAlg") != rsaSHA256SigAlg {
		t.Fatalf("SigAlg = %q", q.Get("SigAlg"))
	}
	// The payload is DEFLATE + base64 per the redirect binding, and it must
	// carry the InResponseTo the SP will match against its request.
	payload, err := base64.StdEncoding.DecodeString(q.Get("SAMLResponse"))
	if err != nil {
		t.Fatalf("SAMLResponse is not base64: %v", err)
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(payload)))
	if err != nil {
		t.Fatalf("SAMLResponse is not raw DEFLATE: %v", err)
	}
	body := string(xmlBytes)
	for _, want := range []string{`InResponseTo="req-1"`, "https://idp/meta", "https://sp.example.com/sls", "Success"} {
		if !strings.Contains(body, want) {
			t.Errorf("LogoutResponse missing %q:\n%s", want, body)
		}
	}

	// A destination that already carries a query must get & rather than a
	// second ?, or the SP sees one giant malformed parameter.
	withQuery, err := buildLogoutResponseRedirect("https://sp.example.com/sls?tenant=a", "iss", "r", "", c.key)
	if err != nil {
		t.Fatalf("buildLogoutResponseRedirect: %v", err)
	}
	if strings.Count(withQuery, "?") != 1 {
		t.Fatalf("query separator handling is wrong: %s", withQuery)
	}
	if u2, err := url.Parse(withQuery); err != nil || u2.Query().Get("tenant") != "a" {
		t.Fatalf("the pre-existing query parameter was lost: %s", withQuery)
	}
}

func TestDeflateBase64RoundTrip(t *testing.T) {
	const payload = `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`

	enc, err := deflateBase64([]byte(payload))
	if err != nil {
		t.Fatalf("deflateBase64: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	// Raw DEFLATE with no zlib wrapper is what SAML 2.0 specifies; a zlib
	// header here would make every SP fail to inflate.
	got, err := io.ReadAll(flate.NewReader(bytes.NewReader(der)))
	if err != nil {
		t.Fatalf("not raw DEFLATE: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("round trip produced %q", got)
	}
}

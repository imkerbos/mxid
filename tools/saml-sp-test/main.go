// Tiny SAML Service Provider for end-to-end verification against MXID.
//
// Why this exists:
//
//   - BookStack / Nextcloud user_saml hide the SAML Response on failure,
//     surface only a generic "login failed" toast, and need the SP-side
//     log file to figure out what was rejected.
//   - The Go unit test (sign_test.go) only proves the IdP can verify its
//     own signature — it can't tell us whether a real PHP / Go SP accepts
//     the wire format.
//
// This binary closes that gap: it pulls the IdP metadata at startup, runs
// crewjam/saml's standard SP middleware, and on a successful round-trip
// dumps the parsed assertion attributes to the browser. Any failure is
// surfaced verbatim in the response body — no log spelunking required.
//
// Usage:
//
//	go run ./tools/saml-sp-test
//
// Then on the IdP:
//
//	1. Create a SAML application with code "saml-test"
//	2. Protocol config → import URL: http://192.168.254.200:4006/saml/metadata
//	3. Access policy → add public allow
//	4. Browser → http://192.168.254.200:4006/
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml/samlsp"
)

func main() {
	rootURLStr := envOr("SP_ROOT_URL", "http://192.168.254.200:4006")
	idpMetadataStr := envOr("IDP_METADATA_URL", "http://192.168.254.200:3500/protocol/saml/saml-test/metadata")

	rootURL, err := url.Parse(rootURLStr)
	if err != nil {
		log.Fatalf("parse SP_ROOT_URL: %v", err)
	}
	idpMetadataURL, err := url.Parse(idpMetadataStr)
	if err != nil {
		log.Fatalf("parse IDP_METADATA_URL: %v", err)
	}

	// Self-signed SP cert+key. Keeps the binary stateless — the IdP holds
	// the public side after it imports our metadata once.
	key, cert := mustMintSelfSigned("mxid-saml-sp-test")

	// Fetch + parse IdP metadata once at startup. Fail-fast surfaces a
	// useful error ("connection refused" / "404") instead of the SP
	// silently 500-ing on every login.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	idpMetadata, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *idpMetadataURL)
	if err != nil {
		log.Fatalf("fetch IdP metadata from %s: %v", idpMetadataStr, err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               key,
		Certificate:       cert,
		IDPMetadata:       idpMetadata,
		AllowIDPInitiated: true, // also exercise IdP-initiated launch from MXID portal
	})
	if err != nil {
		log.Fatalf("init SP: %v", err)
	}

	// /saml/ — the standard ACS / metadata / SLO endpoints expected by
	// the IdP. We expose them under the same prefix the SP middleware
	// generates internally.
	mux := http.NewServeMux()
	mux.Handle("/saml/", samlSP)

	// Protected page — what users see after a successful round-trip.
	// Dumps every SAML attribute received so operators can verify
	// attribute_mapping wiring at a glance.
	mux.Handle("/", samlSP.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := samlsp.SessionFromContext(r.Context())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, `<!doctype html><meta charset="utf-8"><title>SAML SP Test — OK</title>`)
		fmt.Fprintln(w, `<style>body{font-family:system-ui;max-width:760px;margin:40px auto;padding:0 16px}pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow:auto;font-size:13px}</style>`)
		fmt.Fprintln(w, `<h1>SAML SP test — login OK ✓</h1>`)
		fmt.Fprintln(w, `<p>The IdP issued a Response that this SP accepted, validated the XML-DSIG signature on, and converted into a session. Attributes follow.</p>`)
		fmt.Fprintln(w, `<h2>Session attributes</h2><pre>`)
		if jwtSess, ok := s.(samlsp.JWTSessionClaims); ok {
			out, _ := json.MarshalIndent(jwtSess, "", "  ")
			fmt.Fprintln(w, string(out))
		} else if attrSess, ok := s.(interface {
			GetAttributes() samlsp.Attributes
		}); ok {
			out, _ := json.MarshalIndent(attrSess.GetAttributes(), "", "  ")
			fmt.Fprintln(w, string(out))
		} else {
			fmt.Fprintln(w, "(session has no exported attributes)")
		}
		fmt.Fprintln(w, `</pre>`)
		fmt.Fprintln(w, `<p><a href="/saml/logout">Logout (SLO)</a></p>`)
	})))

	listen := envOr("SP_LISTEN", ":4006")
	log.Printf("SAML SP test ready")
	log.Printf("  root URL    : %s", rootURL)
	log.Printf("  IdP metadata: %s", idpMetadataURL)
	log.Printf("  SP metadata : %s/saml/metadata", rootURL)
	log.Printf("  listening   : %s", listen)
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// mustMintSelfSigned generates an RSA-2048 keypair + matching self-signed
// X.509 cert. Used so the SP doesn't need cert files on disk — fine for a
// dev tool, NOT for production.
func mustMintSelfSigned(cn string) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa keygen: %v", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("self-sign: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalf("parse self-signed: %v", err)
	}
	return key, parsed
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

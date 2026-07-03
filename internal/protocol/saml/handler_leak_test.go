package saml

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"go.uber.org/zap"
)

// TestMetadata_SigningCertLoadFailure_DoesNotLeakInternalError guards against a
// regression of the SAML handler leaking raw internal error text (e.g. driver
// errors, file paths, internal hostnames) to the client. Before this fix,
// metadata() responded with "load signing cert: "+err.Error() verbatim; now it
// must respond with a generic, safe message while the real cause is only
// logged server-side.
func TestMetadata_SigningCertLoadFailure_DoesNotLeakInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	appCfg := &resolver.AppConfig{ID: 1, Protocol: "saml", Code: "app1", Status: 1}
	sensitive := "pq: connection refused to internal-db-host.corp:5432"

	appRes := resolver.NewAppResolver(
		func(ctx context.Context, tenantID int64, code string) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, id int64) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, clientID string) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, id int64, certType string) (*resolver.CertConfig, error) { return nil, nil },
		// No certs on file -> loadSignOptions falls back to MintSigningCert.
		func(ctx context.Context, id int64) ([]*resolver.CertConfig, error) { return nil, nil },
		func(ctx context.Context) ([]*resolver.CertConfig, error) { return nil, nil },
		// Minting fails with an internal-looking error that must never reach the client.
		func(ctx context.Context, id int64) (*resolver.CertConfig, error) {
			return nil, errors.New(sensitive)
		},
	)

	h := NewHandler("https://idp.example", "", appRes, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	h.RegisterRoutes(r.Group("/protocol"))

	req := httptest.NewRequest("GET", "/protocol/saml/app1/metadata", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, sensitive) || strings.Contains(body, "internal-db-host") || strings.Contains(body, "pq:") {
		t.Fatalf("response body leaked internal error text: %s", body)
	}
	if !strings.Contains(body, "failed to load signing certificate") {
		t.Fatalf("expected generic safe message in body, got: %s", body)
	}
}

// TestSSORedirect_InvalidSAMLRequest_DoesNotLeakInternalError checks the
// decode-failure path: an unparsable SAMLRequest must still get a generic
// 400 without echoing the underlying base64/XML parse error.
func TestSSORedirect_InvalidSAMLRequest_DoesNotLeakInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	appCfg := &resolver.AppConfig{ID: 1, Protocol: "saml", Code: "app1", Status: 1}
	appRes := resolver.NewAppResolver(
		func(ctx context.Context, tenantID int64, code string) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, id int64) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, clientID string) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, id int64, certType string) (*resolver.CertConfig, error) { return nil, nil },
		func(ctx context.Context, id int64) ([]*resolver.CertConfig, error) { return nil, nil },
		func(ctx context.Context) ([]*resolver.CertConfig, error) { return nil, nil },
		func(ctx context.Context, id int64) (*resolver.CertConfig, error) { return nil, nil },
	)
	h := NewHandler("https://idp.example", "", appRes, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	h.RegisterRoutes(r.Group("/protocol"))

	req := httptest.NewRequest("GET", "/protocol/saml/app1/sso?SAMLRequest=!!!not-valid-base64!!!", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	leaky := []string{"decode SAMLRequest base64", "illegal base64", "parse AuthnRequest:"}
	for _, s := range leaky {
		if strings.Contains(body, s) {
			t.Fatalf("response body leaked internal error text %q: %s", s, body)
		}
	}
	if !strings.Contains(body, "invalid SAMLRequest") {
		t.Fatalf("expected generic message in body, got: %s", body)
	}
}

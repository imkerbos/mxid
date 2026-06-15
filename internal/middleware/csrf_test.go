package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCSRF_RefererOrigin(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https://app.example.com/path", "https://app.example.com"},
		{"https://app.example.com", "https://app.example.com"},
		{"https://app.example.com:8443/x?y=1", "https://app.example.com:8443"},
		{"not-a-url", ""},
	}
	for _, tc := range cases {
		if got := refererOrigin(tc.in); got != tc.want {
			t.Errorf("refererOrigin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func newTestRouter(cfg CSRFConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CSRF(cfg))
	r.GET("/ping", func(c *gin.Context) { c.String(200, "ok") })
	r.POST("/write", func(c *gin.Context) { c.String(200, "ok") })
	r.POST("/health", func(c *gin.Context) { c.String(200, "ok") })
	return r
}

func TestCSRF_SafeMethodsPass(t *testing.T) {
	r := newTestRouter(CSRFConfig{TrustedOrigins: []string{"https://app.test"}})
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET should pass without Origin, got %d", w.Code)
	}
}

func TestCSRF_MissingOriginAndReferer(t *testing.T) {
	r := newTestRouter(CSRFConfig{TrustedOrigins: []string{"https://app.test"}})
	req := httptest.NewRequest(http.MethodPost, "/write", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST without Origin/Referer must be 403, got %d", w.Code)
	}
}

func TestCSRF_AllowedOrigin(t *testing.T) {
	r := newTestRouter(CSRFConfig{TrustedOrigins: []string{"https://app.test"}})
	req := httptest.NewRequest(http.MethodPost, "/write", nil)
	req.Header.Set("Origin", "https://app.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("allowed Origin must pass, got %d", w.Code)
	}
}

func TestCSRF_RejectedOrigin(t *testing.T) {
	r := newTestRouter(CSRFConfig{TrustedOrigins: []string{"https://app.test"}})
	req := httptest.NewRequest(http.MethodPost, "/write", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("evil Origin must be 403, got %d", w.Code)
	}
}

func TestCSRF_RefererFallback(t *testing.T) {
	r := newTestRouter(CSRFConfig{TrustedOrigins: []string{"https://app.test"}})
	req := httptest.NewRequest(http.MethodPost, "/write", nil)
	req.Header.Set("Referer", "https://app.test/some/page")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("matching Referer must pass when Origin missing, got %d", w.Code)
	}
}

func TestCSRF_SkipPathsBypass(t *testing.T) {
	r := newTestRouter(CSRFConfig{
		TrustedOrigins: []string{"https://app.test"},
		SkipPaths:      []string{"/health"},
	})
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("SkipPath must bypass, got %d", w.Code)
	}
}

func TestCSRF_BearerBypass(t *testing.T) {
	r := newTestRouter(CSRFConfig{
		TrustedOrigins:  []string{"https://app.test"},
		AllowBearerAuth: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/write", nil)
	req.Header.Set("Authorization", "Bearer abc.def.ghi")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Bearer auth must bypass, got %d", w.Code)
	}
}

func TestCSRF_TrailingSlashNormalized(t *testing.T) {
	r := newTestRouter(CSRFConfig{TrustedOrigins: []string{"https://app.test/"}})
	req := httptest.NewRequest(http.MethodPost, "/write", nil)
	req.Header.Set("Origin", "https://app.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("trailing slash in config must normalize, got %d", w.Code)
	}
	_ = strings.HasPrefix
}

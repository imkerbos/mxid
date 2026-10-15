package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The OIDC subtree answers CORS for itself, from the registered applications
// rather than from this deployment's origin list. This middleware still runs in
// front of it — the chain is global — so it must not answer on that subtree's
// behalf.
//
// It used to. The OPTIONS branch aborted unconditionally, before the protocol
// layer saw the request, so a public client's token-exchange preflight came
// back 204 with no Access-Control-* headers and the browser refused to send the
// POST. GET requests reached the protocol layer and looked fine, which made the
// failure look like it belonged to the token endpoint specifically.
func TestCORS_SkipPrefixLeavesPreflightToTheSubtree(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(CORSConfig{
		AllowOrigins: []string{"https://console.example.com"},
		SkipPrefixes: []string{"/protocol/"},
	}))
	// Stand-in for the protocol layer's own CORS handling.
	reached := false
	r.Any("/protocol/oidc/token", func(c *gin.Context) {
		reached = true
		c.Header("Access-Control-Allow-Origin", "https://app.example.com")
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodOptions, "/protocol/oidc/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if !reached {
		t.Fatal("the preflight never reached the protocol subtree: the global middleware answered it")
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q, want the subtree's own answer", got)
	}
}

// Everything outside the skipped prefixes keeps the old behaviour: this
// middleware owns the console and portal preflights.
func TestCORS_StillAnswersOutsideTheSkippedPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(CORSConfig{
		AllowOrigins: []string{"https://console.example.com"},
		SkipPrefixes: []string{"/protocol/"},
	}))
	r.Any("/api/v1/console/apps", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/console/apps", nil)
	req.Header.Set("Origin", "https://console.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Errorf("Allow-Origin = %q, want the console origin", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %q: the console IS cookie-authenticated and needs it", got)
	}
}

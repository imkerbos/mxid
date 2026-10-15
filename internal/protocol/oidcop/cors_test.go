package oidcop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// A public client finishes the code exchange from page JavaScript, so /token
// faces a CORS preflight. Two things used to make that impossible, and both are
// pinned here:
//
//   - the global CORS middleware aborted EVERY OPTIONS before the protocol
//     layer could answer, so a preflight came back 204 with no Access-Control-*
//     headers at all and the browser never sent the POST. The endpoints looked
//     CORS-enabled on GET (the library answered those) and broken only on
//     preflight — a confusing way to fail;
//   - zitadel/oidc's default is AllowOriginFunc returning true for every origin
//     together with AllowCredentials, i.e. credentialed cross-origin access
//     from anywhere.
//
// The replacement derives its allow-list from the registered redirect URIs so
// that onboarding a relying party needs no change to MXID's own configuration,
// and never sets Allow-Credentials.

type corsApps struct {
	resolver.AppResolver
	origins []string
	err     error
	calls   int
}

func (c *corsApps) ListBrowserOrigins(context.Context) ([]string, error) {
	c.calls++
	return c.origins, c.err
}

func corsRun(t *testing.T, apps resolver.AppResolver, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(apps, zap.NewNop()))
	r.Any("/protocol/oidc/token", func(c *gin.Context) { c.String(http.StatusOK, "token") })

	req := httptest.NewRequest(method, "/protocol/oidc/token", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "content-type")
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCORS_PreflightFromARegisteredOriginIsAnswered(t *testing.T) {
	apps := &corsApps{origins: []string{"https://app.example.com/login"}}

	w := corsRun(t, apps, http.MethodOptions, "https://app.example.com")

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q, want the reflected origin — without it the browser never sends the token POST", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" || !strings.Contains(got, "POST") {
		t.Errorf("Allow-Methods = %q, want it to include POST", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") || !strings.Contains(got, "Authorization") {
		t.Errorf("Allow-Headers = %q, want Content-Type and Authorization", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin: the response differs by origin and a cache must not reuse it", got)
	}
}

// The endpoints here authenticate with a code, a client secret or a bearer
// token — never the session cookie. Allow-Credentials would invite the browser
// to attach one, and a mistake in the origin comparison would then hand a
// session to a third party.
func TestCORS_NeverAllowsCredentials(t *testing.T) {
	apps := &corsApps{origins: []string{"https://app.example.com/login"}}

	for _, m := range []string{http.MethodOptions, http.MethodPost} {
		w := corsRun(t, apps, m, "https://app.example.com")
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("%s: Allow-Credentials = %q, want it absent", m, got)
		}
	}
}

// An origin nobody registered gets no headers — the browser then blocks the
// call, which is the point.
func TestCORS_UnregisteredOriginGetsNoHeaders(t *testing.T) {
	apps := &corsApps{origins: []string{"https://app.example.com/login"}}

	w := corsRun(t, apps, http.MethodOptions, "https://evil.example.net")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q for an unregistered origin", got)
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (a refused preflight is still a preflight answer)", w.Code)
	}
}

// Nothing wired means deny, not allow.
func TestCORS_NilResolverDenies(t *testing.T) {
	w := corsRun(t, nil, http.MethodOptions, "https://app.example.com")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q with no resolver wired; a missing wiring must fail closed", got)
	}
}

// A same-origin or non-browser caller carries no Origin and must pass straight
// through — the handler still has to run.
func TestCORS_NoOriginPassesThrough(t *testing.T) {
	apps := &corsApps{origins: []string{"https://app.example.com/login"}}
	w := corsRun(t, apps, http.MethodPost, "")
	if w.Code != http.StatusOK || w.Body.String() != "token" {
		t.Errorf("status=%d body=%q, want the handler to run", w.Code, w.Body.String())
	}
}

// The preflight sits in front of every token exchange; reading all registered
// applications on each one would put a query on a latency-sensitive path.
func TestCORS_ResolverIsCached(t *testing.T) {
	apps := &corsApps{origins: []string{"https://app.example.com/login"}}
	for i := 0; i < 5; i++ {
		corsRun(t, apps, http.MethodOptions, "https://app.example.com")
	}
	// Each corsRun builds a fresh middleware, so caching is observable only
	// within one: drive five requests through a single instance instead.
	gin.SetMode(gin.TestMode)
	apps2 := &corsApps{origins: []string{"https://app.example.com/login"}}
	r := gin.New()
	r.Use(CORS(apps2, zap.NewNop()))
	r.Any("/t", func(c *gin.Context) { c.Status(http.StatusOK) })
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodOptions, "/t", nil)
		req.Header.Set("Origin", "https://app.example.com")
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	if apps2.calls != 1 {
		t.Errorf("resolver called %d times for 5 preflights, want 1", apps2.calls)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://app.example.com/login", "https://app.example.com"},
		{"https://App.Example.COM/login", "https://app.example.com"},
		{"https://app.example.com:443/cb", "https://app.example.com"},
		{"http://localhost:80/cb", "http://localhost"},
		{"http://localhost:3000/cb", "http://localhost:3000"},
		{"https://app.example.com:8443/cb", "https://app.example.com:8443"},
		// A native client's custom scheme has no web origin.
		{"com.example.app://callback", ""},
		{"/relative/cb", ""},
		{"", ""},
		{"https:///nohost", ""},
	}
	for _, tc := range tests {
		if got := NormalizeOrigin(tc.in); got != tc.want {
			t.Errorf("NormalizeOrigin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The consent grant handler takes return_to from the request body, appends a
// freshly minted confirmation token to it, and hands it back for the browser to
// navigate to. The SPA validates the value first, but the front end is not a
// security boundary — the server has to reject the hostile shapes itself.
//
// These tests pin the WIRING, not the validator. saferedirect's own tests cover
// which shapes are hostile; delete the call from the handler and only this file
// notices.

func postConsent(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// confirm is nil (token minting off) and consentSvc is nil, which is safe
	// here: validation happens before either is reached. A request that gets
	// past validation panics on the nil service, which is itself the signal
	// that the guard did not fire.
	h := &consentHandler{}

	r := gin.New()
	r.Use(withUser(1))
	r.POST("/consent", h.grant)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestConsentGrant_RejectsHostileReturnTo(t *testing.T) {
	for name, returnTo := range map[string]string{
		"javascript scheme": "javascript:alert(1)",
		"data scheme":       "data:text/html,<script>alert(1)</script>",
		"protocol-relative": "//evil.example/collect",
		"backslash smuggle": "/\\evil.example",
		"userinfo smuggle":  "https://id.example.com@evil.example/",
		"header injection":  "/path\r\nX-Injected: 1",
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("handler reached its business logic with return_to=%q — the server-side "+
						"shape check is not wired in, so this value would come back decorated with a "+
						"confirmation token for the browser to navigate to (panic: %v)", returnTo, rec)
				}
			}()

			w := postConsent(t, `{"app_id":"1","return_to":`+quote(returnTo)+`}`)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("return_to=%q got HTTP %d, want 400", returnTo, w.Code)
			}
		})
	}
}

// quote is a minimal JSON string encoder for the fixtures above — the values
// carry backslashes and control characters that must survive into the body
// exactly as written.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

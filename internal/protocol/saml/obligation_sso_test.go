package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/session"
)

// A session held back by a forced password change or a mandatory MFA
// enrollment must not be able to single-sign-on. The SPA gates confine it to
// the remediation route, but /protocol/saml/<app>/sso reads the session store
// itself — before the resolver rejected pending sessions, anyone holding a
// reset password could trade a portal cookie for a signed assertion without
// ever changing it.
//
// The discriminator is deliberate: a blocked request bounces to the portal
// login (302), an unblocked one reaches the app-access gate and is refused
// there (403, denyChecker). A 403 therefore proves the session resolved, which
// is what makes the clean-session rows a real counter-test rather than a
// restatement of the block.
func TestProcessSSO_ObligationPendingSession_IssuesNoAssertion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		namespace  string
		cookie     string
		pwdPending bool
		mfaPending bool
		wantStatus int
	}{
		{"pwd pending, portal cookie", session.NamespacePortal, "mxid_portal_sid", true, false, http.StatusFound},
		{"mfa pending, portal cookie", session.NamespacePortal, "mxid_portal_sid", false, true, http.StatusFound},
		{"pwd pending, proto cookie", session.NamespaceProtocol, "mxid_proto_sid", true, false, http.StatusFound},
		{"mfa pending, proto cookie", session.NamespaceProtocol, "mxid_proto_sid", false, true, http.StatusFound},
		{"clean session, portal cookie", session.NamespacePortal, "mxid_portal_sid", false, false, http.StatusForbidden},
		{"clean session, proto cookie", session.NamespaceProtocol, "mxid_proto_sid", false, false, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			mgr := session.NewManager(rdb, time.Hour, 12*time.Hour)
			if tc.pwdPending {
				mgr.SetPwdChangeDecider(func(context.Context, int64, int64) bool { return true })
			}
			if tc.mfaPending {
				mgr.SetEnrollDecider(func(context.Context, int64, int64) bool { return true })
			}
			sess, err := mgr.Create(context.Background(), tc.namespace, 5, 1, "1.2.3.4", "ua", "pwd")
			if err != nil {
				t.Fatalf("Create session: %v", err)
			}

			app := &resolver.AppConfig{ID: 9, TenantID: 1, Protocol: "saml", Code: "app1", Status: 1}
			appRes := resolver.NewAppResolver(
				func(context.Context, int64, string) (*resolver.AppConfig, error) { return app, nil },
				func(context.Context, int64) (*resolver.AppConfig, error) { return app, nil },
				func(context.Context, string) (*resolver.AppConfig, error) { return app, nil },
				func(context.Context, int64, string) (*resolver.CertConfig, error) { return nil, nil },
				func(context.Context, int64) ([]*resolver.CertConfig, error) { return nil, nil },
				func(context.Context) ([]*resolver.CertConfig, error) { return nil, nil },
				func(context.Context, int64) (*resolver.CertConfig, error) { return nil, nil },
				func(context.Context) ([]string, error) { return nil, nil },
			)

			h := NewHandler("https://idp.example", "https://portal.example",
				appRes, nil, resolver.NewSessionResolver(rdb), nil, nil, zap.NewNop())
			h.access = denyChecker{}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest("GET", "/protocol/saml/app1/sso", nil)
			req.AddCookie(&http.Cookie{Name: tc.cookie, Value: sess.ID})
			c.Request = req

			// IdP-initiated (requestID == "") so the confirm step is skipped.
			h.processSSO(c, "app1", "", "")

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%q, location=%q)",
					w.Code, tc.wantStatus, w.Body.String(), w.Header().Get("Location"))
			}
			if tc.wantStatus == http.StatusFound {
				if loc := w.Header().Get("Location"); !strings.Contains(loc, "/login?protocol=saml") {
					t.Fatalf("Location = %q, want the portal login bounce", loc)
				}
				if strings.Contains(w.Body.String(), "SAMLResponse") {
					t.Fatalf("body contains a SAMLResponse: %q", w.Body.String())
				}
			}
		})
	}
}

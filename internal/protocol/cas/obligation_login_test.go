package cas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/session"
)

// A session held back by a forced password change or a mandatory MFA
// enrollment must not get a service ticket. The SPA gates confine it to the
// remediation route, but /protocol/cas/<app>/login reads the session store
// itself — before the resolver rejected pending sessions, a portal cookie was
// enough to obtain a ticket without ever settling the obligation.
func TestCASLogin_ObligationPendingSession_IssuesNoTicket(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const service = "https://app.example/cb"

	cases := []struct {
		name       string
		namespace  string
		cookie     string
		pwdPending bool
		mfaPending bool
		wantTicket bool
	}{
		{"pwd pending, portal cookie", session.NamespacePortal, "mxid_portal_sid", true, false, false},
		{"mfa pending, portal cookie", session.NamespacePortal, "mxid_portal_sid", false, true, false},
		{"pwd pending, proto cookie", session.NamespaceProtocol, "mxid_proto_sid", true, false, false},
		{"mfa pending, proto cookie", session.NamespaceProtocol, "mxid_proto_sid", false, true, false},
		{"clean session, portal cookie", session.NamespacePortal, "mxid_portal_sid", false, false, true},
		{"clean session, proto cookie", session.NamespaceProtocol, "mxid_proto_sid", false, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rdb := miniredisClient(t)
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

			cfg, _ := json.Marshal(map[string]any{"service_urls": []string{service}})
			app := &resolver.AppConfig{
				ID: 9, TenantID: 1, Code: "app1", Protocol: "cas", Status: 1, ProtocolConfig: cfg,
			}
			h := &Handler{
				issuer:    "https://idp.example",
				portalURL: "https://portal.example",
				appRes:    stubAppResolver{app: app},
				idRes: stubIdentityResolver{info: &resolver.IdentityInfo{
					ID: 5, TenantID: 1, Username: "alice",
				}},
				sessRes: resolver.NewSessionResolver(rdb),
				store:   NewTicketStore(rdb),
				logger:  zap.NewNop(),
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Params = gin.Params{{Key: "app_code", Value: "app1"}}
			req := httptest.NewRequest("GET",
				"/protocol/cas/app1/login?idp_initiated=1&service="+url.QueryEscape(service), nil)
			req.AddCookie(&http.Cookie{Name: tc.cookie, Value: sess.ID})
			c.Request = req

			h.login(c)

			loc := w.Header().Get("Location")
			if tc.wantTicket {
				if w.Code != http.StatusFound || !strings.Contains(loc, "ticket=ST-") {
					t.Fatalf("a clean session must get a ticket: status=%d location=%q body=%q",
						w.Code, loc, w.Body.String())
				}
				return
			}
			if strings.Contains(loc, "ticket=") {
				t.Fatalf("location = %q — a pending session was handed a service ticket", loc)
			}
			if w.Code != http.StatusFound || !strings.Contains(loc, "/login?protocol=cas") {
				t.Fatalf("status=%d location=%q, want the portal login bounce (body=%q)",
					w.Code, loc, w.Body.String())
			}
		})
	}
}

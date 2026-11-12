package oidcop

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
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/session"
)

// A session held back by a forced password change or a mandatory MFA
// enrollment must not complete an authorization request. The SPA gates confine
// it to the remediation route, but the login bridge reads the session store
// itself — before the resolver rejected pending sessions, a portal cookie was
// enough to be issued an authorization code without ever settling the
// obligation.
func TestLoginBridgeHandle_ObligationPendingSession_IssuesNoCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name         string
		namespace    string
		cookie       string
		pwdPending   bool
		mfaPending   bool
		wantComplete bool
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
			mr := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			mgr := session.NewManager(rdb, time.Hour, 12*time.Hour)
			if tc.pwdPending {
				mgr.SetPwdChangeDecider(func(context.Context, int64, int64) bool { return true })
			}
			if tc.mfaPending {
				mgr.SetEnrollDecider(func(context.Context, int64, int64) bool { return true })
			}
			ctx := context.Background()
			sess, err := mgr.Create(ctx, tc.namespace, confirmTestUserID, 1, "1.2.3.4", "ua", "pwd")
			if err != nil {
				t.Fatalf("Create session: %v", err)
			}

			storage := NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())
			req, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
				ClientID:     "app1",
				RedirectURI:  "https://app.example.com/callback",
				Scopes:       []string{"openid"},
				ResponseType: oidc.ResponseTypeCode,
			}, "")
			if err != nil {
				t.Fatalf("CreateAuthRequest: %v", err)
			}
			authReqID := req.GetID()

			apps := &fakeBridgeAppResolver{app: &resolver.AppConfig{
				ID: confirmTestAppID, ClientID: "app1", Code: "app1-code", Protocol: "oidc",
				Status: 1, FirstParty: true, RequireConsent: false,
			}}
			// confirm nil → no confirmation gate, so the only thing that can
			// stop the flow is the session itself.
			bridge := NewLoginBridge(storage, apps, resolver.NewSessionResolver(rdb), nil, nil, nil,
				func(context.Context, string) string { return "https://issuer.example.com/callback" },
				func(id string) string { return "https://issuer.example.com/oidc-login?authRequestID=" + id },
				"https://portal.example.com", nil,
			)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			httpReq := httptest.NewRequest(http.MethodGet,
				"/protocol/oidc/oidc-login?authRequestID="+authReqID, nil)
			httpReq.AddCookie(&http.Cookie{Name: tc.cookie, Value: sess.ID})
			c.Request = httpReq
			bridge.Handle(c)

			loc := w.Header().Get("Location")
			got, arErr := storage.AuthRequestByID(ctx, authReqID)
			if tc.wantComplete {
				if loc != "https://issuer.example.com/callback" {
					t.Fatalf("a clean session must complete: location=%q body=%q", loc, w.Body.String())
				}
				if arErr != nil || !got.Done() {
					t.Fatalf("auth request not Done for a clean session (err=%v)", arErr)
				}
				return
			}
			if arErr == nil && got.Done() {
				t.Fatal("auth request Done() = true — a pending session was issued an authorization code")
			}
			if !strings.HasPrefix(loc, "https://portal.example.com/login?return_to=") {
				t.Fatalf("location = %q, want the portal login bounce", loc)
			}
		})
	}
}

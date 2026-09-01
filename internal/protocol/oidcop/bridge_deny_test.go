package oidcop

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Cancel on the confirm page must end the flow, not restart it.
//
// Without a sso_deny branch this did not fail — it looped. Cancel returns the
// browser to this endpoint carrying sso_deny=1; nothing read it, so the request
// fell through to the token check, found no token, and bounced to the confirm
// page again. Pressing Cancel redisplayed the page being cancelled, with no
// exit but the back button. CAS and SAML both handled it; only OIDC did not.
func TestLoginBridgeHandle_Deny_DoesNotReturnToConsent(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	w := runDenyHandle(bridge, authReqID)

	loc := w.Header().Get("Location")
	if strings.Contains(loc, "/consent") {
		t.Fatalf("Location = %q — Cancel sent the user back to the page they "+
			"were cancelling; that is the loop this branch exists to break", loc)
	}

	// The request must not have completed either: declining is not consenting.
	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err == nil && got.Done() {
		t.Fatal("auth request Done() = true after a denial — Cancel must never " +
			"produce an authorization code")
	}
}

// The auth request is answered, so it must not survive for a replay of the same
// URL to resume a flow the user rejected.
func TestLoginBridgeHandle_Deny_DeletesAuthRequest(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	runDenyHandle(bridge, authReqID)

	if _, err := storage.AuthRequestByID(context.Background(), authReqID); err == nil {
		t.Fatal("the auth request is still live after a denial — replaying the " +
			"same URL would resume a flow the user said no to")
	}
}

// With an authorizer wired, the RP is told access_denied at ITS OWN registered
// redirect_uri. The application asked a question and is entitled to hear that
// the answer was no, rather than hanging on a callback that never arrives.
func TestLoginBridgeHandle_Deny_AnswersRPWithAccessDenied(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)
	bridge.authorizer = &fakeAuthorizer{}

	w := runDenyHandle(bridge, authReqID)

	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/callback") {
		t.Fatalf("Location = %q, want the client's REGISTERED redirect_uri — "+
			"anything taken from the request's own query string here would be "+
			"an open redirect", loc)
	}
	if !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("Location = %q, want error=access_denied (OIDC Core 3.1.2.6)", loc)
	}
}

// No authorizer wired: Cancel must still leave the confirm page rather than
// loop. The fallback is a plain redirect, not an error the RP can parse — but
// looping is the one outcome that is not acceptable.
func TestLoginBridgeHandle_Deny_FallsBackWithoutAuthorizer(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)
	// newConfirmBridge already passes a nil authorizer.

	w := runDenyHandle(bridge, authReqID)

	loc := w.Header().Get("Location")
	if strings.Contains(loc, "/consent") {
		t.Fatalf("Location = %q — even with no authorizer, Cancel must not "+
			"return to the confirm page", loc)
	}
	if loc == "" {
		t.Fatal("no redirect at all: Cancel left the user on a blank response")
	}
}

// A denial on an IdP-initiated launch is not reachable through the UI (that
// path shows no confirm page), and must not be honoured as a shortcut past the
// gate: it stays seamless, exactly as before.
func TestLoginBridgeHandle_Deny_IgnoredWhenIdPInitiated(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, true)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	w := runDenyHandle(bridge, authReqID)

	if loc := w.Header().Get("Location"); loc != "https://issuer.example.com/callback" {
		t.Fatalf("Location = %q, want op's callback: an IdP-initiated launch "+
			"never showed a confirm page, so there is nothing to deny", loc)
	}
}

func runDenyHandle(bridge *LoginBridge, authReqID string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet,
		"/protocol/oidc/oidc-login?authRequestID="+authReqID+"&sso_deny=1", nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq
	bridge.Handle(c)
	return w
}

// fakeAuthorizer supplies only what op.AuthRequestError reads: an encoder to
// build the error response and a logger to record it. Everything else is left
// nil so a call to it would panic loudly rather than pass silently.
type fakeAuthorizer struct{ op.Authorizer }

func (f *fakeAuthorizer) Encoder() httphelper.Encoder { return errEncoder{} }
func (f *fakeAuthorizer) Logger() *slog.Logger        { return slog.Default() }

// errEncoder serialises the two fields of an oidc.Error the redirect needs.
// Written by hand rather than pulling gorilla/schema in as a test-only
// dependency; op's real encoder does the same job over the full struct.
type errEncoder struct{}

func (errEncoder) Encode(src any, dst map[string][]string) error {
	e, ok := src.(*oidc.Error)
	if !ok {
		return nil
	}
	dst["error"] = []string{string(e.ErrorType)}
	if e.Description != "" {
		dst["error_description"] = []string{e.Description}
	}
	if e.State != "" {
		dst["state"] = []string{e.State}
	}
	return nil
}

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
	"github.com/imkerbos/mxid/pkg/ssoflow"
)

// fakeBridgeAppResolver resolves a single first-party app. onGetApp, if set,
// runs before the app is returned — used to simulate the auth request
// expiring/being deleted concurrently between the initial AuthRequestByID
// lookup (bridge.go:74) and the later AuthRequestDone call (bridge.go:117),
// which is the externally-triggerable race the fix covers.
type fakeBridgeAppResolver struct {
	resolver.AppResolver
	app      *resolver.AppConfig
	onGetApp func()
}

func (f *fakeBridgeAppResolver) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	if f.onGetApp != nil {
		f.onGetApp()
	}
	return f.app, nil
}

type fakeBridgeSessionResolver struct {
	resolver.SessionResolver
	sess *resolver.SSOSession
}

func (f *fakeBridgeSessionResolver) GetSSOSession(_ context.Context, _ string) (*resolver.SSOSession, error) {
	return f.sess, nil
}

func (f *fakeBridgeSessionResolver) GetProtocolSSOSession(_ context.Context, _ string) (*resolver.SSOSession, error) {
	return f.sess, nil
}

// TestLoginBridgeHandle_AuthRequestExpiredDuringCompletion proves that when
// AuthRequestDone (bridge.go:117) fails because the auth request vanished
// between the initial lookup and completion (e.g. it expired mid-flight — an
// externally triggerable race, since the auth request TTL is attacker/
// client-controlled by how long they sit on the login page), Handle now
// mirrors the bridge.go:74-78 "unknown or expired auth request" 400 response
// instead of the previous unconditional 500.
func TestLoginBridgeHandle_AuthRequestExpiredDuringCompletion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage := NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())

	ctx := context.Background()
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

	app := &resolver.AppConfig{
		ID:             1,
		ClientID:       "app1",
		Protocol:       "oidc",
		Status:         1,
		FirstParty:     true,
		RequireConsent: false,
	}
	apps := &fakeBridgeAppResolver{
		app: app,
		// Simulate the race: the auth request expires/is deleted right after
		// Handle's initial AuthRequestByID succeeded, but before it reaches
		// AuthRequestDone.
		onGetApp: func() {
			if err := storage.DeleteAuthRequest(ctx, authReqID); err != nil {
				t.Fatalf("DeleteAuthRequest: %v", err)
			}
		},
	}
	sessions := &fakeBridgeSessionResolver{sess: &resolver.SSOSession{
		ID:        "sess1",
		UserID:    42,
		TenantID:  1,
		AuthType:  "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	}}

	bridge := NewLoginBridge(storage, apps, sessions, nil, nil, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

// fakeParticipationTracker records every Track call so tests can assert the
// WS2 back-channel-logout participation index is populated when an auth
// request completes for a protocol-namespace session.
type fakeParticipationTracker struct {
	calls []trackCall
}

type trackCall struct {
	sid   string
	appID int64
	ttl   time.Duration
}

func (f *fakeParticipationTracker) Track(_ context.Context, sid string, appID int64, ttl time.Duration) error {
	f.calls = append(f.calls, trackCall{sid: sid, appID: appID, ttl: ttl})
	return nil
}

// TestLoginBridgeHandle_TracksParticipation proves that when a protocol
// (mxid_proto_sid) session completes login for a client, the bridge records
// (sid, appID) in the participation tracker — the data WS2 back-channel
// logout fan-out reads to know which RPs to notify. IdP-initiated / portal-
// fallback logins (protoSID == "") must NOT be tracked (passwordless logins
// never mint a protocol session, so there is nothing to correlate).
func TestLoginBridgeHandle_TracksParticipation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage := NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())

	ctx := context.Background()
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

	app := &resolver.AppConfig{
		ID: 77, ClientID: "app1", Protocol: "oidc", Status: 1,
		FirstParty: true, RequireConsent: false,
	}
	apps := &fakeBridgeAppResolver{app: app}
	sessions := &fakeBridgeSessionResolver{sess: &resolver.SSOSession{
		ID:        "proto-sess-1",
		UserID:    42,
		TenantID:  1,
		AuthType:  "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	tracker := &fakeParticipationTracker{}

	bridge := NewLoginBridge(storage, apps, sessions, nil, nil, tracker,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "proto-sess-1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	if len(tracker.calls) != 1 {
		t.Fatalf("Track calls = %d, want 1 (%+v)", len(tracker.calls), tracker.calls)
	}
	if got := tracker.calls[0]; got.sid != "proto-sess-1" || got.appID != 77 {
		t.Errorf("Track call = %+v, want sid=proto-sess-1 appID=77", got)
	}
	if tracker.calls[0].ttl <= 0 {
		t.Errorf("Track ttl = %v, want > 0 (mirrors session's remaining absolute window)", tracker.calls[0].ttl)
	}
}

// TestLoginBridgeHandle_PortalFallbackDoesNotTrackParticipation proves that
// an IdP-initiated / portal-fallback login (protoSID == "", no
// mxid_proto_sid cookie) does NOT call Track — WS1 parity: passwordless
// logins never mint a protocol session, so there is nothing to correlate for
// back-channel logout.
func TestLoginBridgeHandle_PortalFallbackDoesNotTrackParticipation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage := NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())

	ctx := context.Background()
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

	app := &resolver.AppConfig{
		ID: 77, ClientID: "app1", Protocol: "oidc", Status: 1,
		FirstParty: true, RequireConsent: false,
	}
	apps := &fakeBridgeAppResolver{app: app}
	sessions := &fakeBridgeSessionResolver{sess: &resolver.SSOSession{
		ID:        "portal-sess-1",
		UserID:    42,
		TenantID:  1,
		AuthType:  "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	tracker := &fakeParticipationTracker{}

	bridge := NewLoginBridge(storage, apps, sessions, nil, nil, tracker,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_portal_sid", Value: "portal-sess-1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	if len(tracker.calls) != 0 {
		t.Fatalf("Track calls = %d, want 0 (portal-fallback session must not be tracked): %+v", len(tracker.calls), tracker.calls)
	}
}

// fakeAccessChecker is a stub AccessChecker for bridge tests: returns the
// configured decision/error for every call.
type fakeAccessChecker struct {
	allowed bool
	reason  string
	err     error
}

func (f *fakeAccessChecker) CheckAppAccess(_ context.Context, _, _, _ int64) (bool, string, error) {
	return f.allowed, f.reason, f.err
}

// newAccessTestFixture builds a fresh storage + pending auth request + first-
// party no-consent app + authenticated session, shared by the access-policy
// enforcement tests below.
func newAccessTestFixture(t *testing.T) (storage *Storage, authReqID string, apps *fakeBridgeAppResolver, sessions *fakeBridgeSessionResolver) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage = NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())

	ctx := context.Background()
	req, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "app1",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	authReqID = req.GetID()

	apps = &fakeBridgeAppResolver{app: &resolver.AppConfig{
		ID: 77, ClientID: "app1", Code: "app1-code", Protocol: "oidc", Status: 1,
		FirstParty: true, RequireConsent: false,
	}}
	sessions = &fakeBridgeSessionResolver{sess: &resolver.SSOSession{
		ID:        "sess1",
		UserID:    42,
		TenantID:  1,
		AuthType:  "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	return storage, authReqID, apps, sessions
}

// TestLoginBridgeHandle_AccessDenied proves that when the access adapter
// denies the user for the app, Handle does NOT complete the auth request (no
// AuthRequestDone / no redirect to op's callback) and instead redirects to
// the portal "no access" page — porting the hand-rolled engine's
// CheckAppAccess enforcement (internal/protocol/oidc/handler.go:373-386)
// into the zitadel bridge.
func TestLoginBridgeHandle_AccessDenied(t *testing.T) {
	storage, authReqID, apps, sessions := newAccessTestFixture(t)
	access := &fakeAccessChecker{allowed: false, reason: "no-rule-matched"}

	bridge := NewLoginBridge(storage, apps, sessions, nil, access, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/no-access") {
		t.Fatalf("Location = %q, want redirect to the portal no-access page", loc)
	}
	if strings.Contains(loc, "issuer.example.com/callback") {
		t.Fatalf("Location = %q, must NOT redirect to op's callback (auth request must not complete)", loc)
	}

	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if got.Done() {
		t.Fatalf("auth request Done() = true, want false: access-denied user must not complete login")
	}
}

// TestLoginBridgeHandle_AccessAdapterError_FailsClosed proves that an access
// adapter error denies rather than admitting the user (fail-closed, matching
// the hand-rolled engine's redirectError(..., "server_error", ...) branch on
// a CheckAppAccess error) — the auth request must not complete.
func TestLoginBridgeHandle_AccessAdapterError_FailsClosed(t *testing.T) {
	storage, authReqID, apps, sessions := newAccessTestFixture(t)
	access := &fakeAccessChecker{err: context.DeadlineExceeded}

	bridge := NewLoginBridge(storage, apps, sessions, nil, access, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusInternalServerError, w.Body.String())
	}

	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if got.Done() {
		t.Fatalf("auth request Done() = true, want false: an access-adapter error must fail closed")
	}
}

// TestLoginBridgeHandle_AccessAllowed_ProceedsToCallback proves the allow
// path: when the access adapter allows the user, Handle proceeds exactly as
// it would with access checking disabled — auth request completes and the
// response redirects to op's callback.
func TestLoginBridgeHandle_AccessAllowed_ProceedsToCallback(t *testing.T) {
	storage, authReqID, apps, sessions := newAccessTestFixture(t)
	access := &fakeAccessChecker{allowed: true}

	bridge := NewLoginBridge(storage, apps, sessions, nil, access, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if loc != "https://issuer.example.com/callback" {
		t.Fatalf("Location = %q, want op's callback URL", loc)
	}

	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if !got.Done() {
		t.Fatalf("auth request Done() = false, want true: an allowed user must complete login")
	}
}

// --- WS7: SSO login-confirmation gate ---------------------------------------

const (
	confirmTestUserID int64 = 42
	confirmTestAppID  int64 = 77
)

// newConfirmTestFixture builds a fresh storage + confirm store + first-party
// no-consent app + authenticated (mxid_proto_sid) session for user 42 / app 77.
// idpInitiated controls whether the pending auth request is tagged as a portal
// app-list launch (idp_initiated=1) — the seamless path — or a plain
// SP-initiated authorize request that must present a one-time sso_confirm token.
func newConfirmTestFixture(t *testing.T, idpInitiated bool) (storage *Storage, confirm *ssoflow.ConfirmStore, authReqID string, apps *fakeBridgeAppResolver, sessions *fakeBridgeSessionResolver) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage = NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())
	confirm = ssoflow.NewConfirmStore(rdb)

	ctx := context.Background()
	if idpInitiated {
		ctx = contextWithIdpInitiated(ctx, true)
	}
	req, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "app1",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	authReqID = req.GetID()

	apps = &fakeBridgeAppResolver{app: &resolver.AppConfig{
		ID: confirmTestAppID, ClientID: "app1", Code: "app1-code", Protocol: "oidc", Status: 1,
		FirstParty: true, RequireConsent: false,
	}}
	sessions = &fakeBridgeSessionResolver{sess: &resolver.SSOSession{
		ID:        "sess1",
		UserID:    confirmTestUserID,
		TenantID:  1,
		AuthType:  "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	return storage, confirm, authReqID, apps, sessions
}

// newConfirmBridge builds a LoginBridge over the fixture with the confirm store
// wired (access + participation disabled — those are covered elsewhere).
func newConfirmBridge(storage *Storage, confirm *ssoflow.ConfirmStore, apps *fakeBridgeAppResolver, sessions *fakeBridgeSessionResolver) *LoginBridge {
	return NewLoginBridge(storage, apps, sessions, confirm, nil, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/oidc-login?authRequestID=" + id },
		"https://portal.example.com",
	)
}

// runConfirmHandle drives Handle for the given auth request with an
// mxid_proto_sid cookie and an optional sso_confirm query param.
func runConfirmHandle(bridge *LoginBridge, authReqID, ssoConfirm string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	target := "/protocol/oidc/oidc-login?authRequestID=" + authReqID
	if ssoConfirm != "" {
		target += "&sso_confirm=" + ssoConfirm
	}
	httpReq := httptest.NewRequest(http.MethodGet, target, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq
	bridge.Handle(c)
	return w
}

// TestLoginBridgeHandle_SPInitiated_NoToken_RequiresConfirm proves the core
// WS7 gate: an SP-initiated authorize request (no idp_initiated flag) with NO
// sso_confirm token does NOT complete — it bounces to the portal confirm page,
// mirroring the hand-rolled engine's redirectToConsent branch
// (internal/protocol/oidc/handler.go:404).
func TestLoginBridgeHandle_SPInitiated_NoToken_RequiresConfirm(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	w := runConfirmHandle(bridge, authReqID, "")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/consent?app_id=77") {
		t.Fatalf("Location = %q, want redirect to the portal confirm page", loc)
	}
	if strings.Contains(loc, "issuer.example.com/callback") {
		t.Fatalf("Location = %q, must NOT complete to op's callback without confirmation", loc)
	}
	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if got.Done() {
		t.Fatalf("auth request Done() = true, want false: SP-initiated login must confirm first")
	}
}

// TestLoginBridgeHandle_SPInitiated_ValidToken_Completes proves the happy path:
// a valid one-time sso_confirm token (minted for the same user+app) satisfies
// the gate — the auth request completes and redirects to op's callback.
func TestLoginBridgeHandle_SPInitiated_ValidToken_Completes(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	tok, err := confirm.Issue(context.Background(), confirmTestUserID, confirmTestAppID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	w := runConfirmHandle(bridge, authReqID, tok)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://issuer.example.com/callback" {
		t.Fatalf("Location = %q, want op's callback URL", loc)
	}
	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if !got.Done() {
		t.Fatalf("auth request Done() = false, want true: a valid sso_confirm token must complete login")
	}
}

// TestLoginBridgeHandle_SPInitiated_ReplayedToken_Rejected proves single-use
// enforcement holds through the bridge: a token already consumed by one login
// is rejected on a second (fresh) auth request — the replay bounces to confirm
// and does not complete.
func TestLoginBridgeHandle_SPInitiated_ReplayedToken_Rejected(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	tok, err := confirm.Issue(context.Background(), confirmTestUserID, confirmTestAppID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// First use consumes the token and completes.
	if w := runConfirmHandle(bridge, authReqID, tok); w.Code != http.StatusFound ||
		w.Header().Get("Location") != "https://issuer.example.com/callback" {
		t.Fatalf("first use: status=%d loc=%q, want 302 → callback", w.Code, w.Header().Get("Location"))
	}

	// A brand-new SP-initiated auth request replaying the SAME token must fail:
	// GetDel already deleted it, so Consume returns false.
	req2, err := storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     "app1",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest#2: %v", err)
	}
	authReqID2 := req2.GetID()

	w := runConfirmHandle(bridge, authReqID2, tok)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "/consent?app_id=77") {
		t.Fatalf("Location = %q, want redirect to confirm page on replay", loc)
	}
	got, err := storage.AuthRequestByID(context.Background(), authReqID2)
	if err != nil {
		t.Fatalf("AuthRequestByID#2: %v", err)
	}
	if got.Done() {
		t.Fatalf("auth request Done() = true, want false: a replayed sso_confirm token must be rejected")
	}
}

// TestLoginBridgeHandle_SPInitiated_AlreadyConsentedApp_StillConfirms proves
// there is NO persisted-consent shortcut: the fixture app is first-party with
// require_consent=false (exactly the shape the old HasAll gate auto-skipped),
// yet an SP-initiated login with no token STILL confirms — Google-style
// per-login confirmation, matching the hand-rolled engine.
func TestLoginBridgeHandle_SPInitiated_AlreadyConsentedApp_StillConfirms(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, false)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	w := runConfirmHandle(bridge, authReqID, "")

	if loc := w.Header().Get("Location"); !strings.Contains(loc, "/consent?app_id=77") {
		t.Fatalf("Location = %q, want confirm page even for a first-party no-consent app (no shortcut)", loc)
	}
	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if got.Done() {
		t.Fatalf("auth request Done() = true, want false: no HasAll shortcut for SP-initiated")
	}
}

// TestLoginBridgeHandle_IdPInitiated_Seamless proves the IdP-initiated (portal
// app-list launch, idp_initiated=1) path stays seamless: NO token is required
// and the auth request completes straight to op's callback — matching the
// hand-rolled engine's `if !idpInitiated` guard.
func TestLoginBridgeHandle_IdPInitiated_Seamless(t *testing.T) {
	storage, confirm, authReqID, apps, sessions := newConfirmTestFixture(t, true)
	bridge := newConfirmBridge(storage, confirm, apps, sessions)

	w := runConfirmHandle(bridge, authReqID, "")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://issuer.example.com/callback" {
		t.Fatalf("Location = %q, want op's callback URL (IdP-initiated must be seamless)", loc)
	}
	got, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if !got.Done() {
		t.Fatalf("auth request Done() = false, want true: IdP-initiated launch must complete without a token")
	}
}

// TestStorageCreateAuthRequest_PersistsIdpInitiated proves the context flag set
// by the withIdpInitiated wrapper survives into the persisted auth request
// (the plumbing the bridge's IdP-initiated branch depends on), and defaults
// false when absent.
func TestStorageCreateAuthRequest_PersistsIdpInitiated(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage := NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())

	base := &oidc.AuthRequest{
		ClientID: "app1", RedirectURI: "https://app.example.com/callback",
		Scopes: []string{"openid"}, ResponseType: oidc.ResponseTypeCode,
	}

	spReq, err := storage.CreateAuthRequest(context.Background(), base, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest (SP): %v", err)
	}
	if got := spReq.(*authRequest).IdpInitiated; got {
		t.Fatalf("SP-initiated IdpInitiated = true, want false")
	}

	idpReq, err := storage.CreateAuthRequest(contextWithIdpInitiated(context.Background(), true), base, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest (IdP): %v", err)
	}
	if got := idpReq.(*authRequest).IdpInitiated; !got {
		t.Fatalf("IdP-initiated IdpInitiated = false, want true")
	}
}

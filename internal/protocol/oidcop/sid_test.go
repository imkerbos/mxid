package oidcop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// TestIDToken_Sid proves the shared protocol session id survives the auth
// request's Redis round-trip and is emitted as the id_token `sid` claim via
// Storage.SetUserinfoFromRequest, the op.CanSetUserinfoFromRequest hook the
// zitadel/oidc library calls while building id_token claims
// (pkg/op/token.go CreateIDToken). OIDC back-channel logout (WS2) depends on
// this sid matching the logout_token's sid for the same session.
func TestIDToken_Sid(t *testing.T) {
	storage := newSidTestStorage(t)
	ctx := context.Background()

	authReqID := createTestAuthRequest(t, storage)
	const protoSID = "proto-sid-123"
	if err := storage.AuthRequestDone(ctx, authReqID, "42", time.Now(), []string{"pwd"}, protoSID); err != nil {
		t.Fatalf("AuthRequestDone: %v", err)
	}

	// Restore from Redis exactly as op does between the login bridge and
	// token issuance — proves sessionID round-trips like every other field.
	restored, err := storage.AuthRequestByID(ctx, authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	sr, ok := restored.(interface{ GetSessionID() string })
	if !ok {
		t.Fatalf("restored auth request does not implement GetSessionID()")
	}
	if got := sr.GetSessionID(); got != protoSID {
		t.Fatalf("GetSessionID() after restore = %q, want %q", got, protoSID)
	}

	assertSidClaim(t, storage, restored, protoSID)
}

// TestIDToken_Sid_AbsentWhenNoSession proves no `sid` claim is emitted when
// the auth request never got a session id — the id_token must not carry a
// fabricated or empty sid.
func TestIDToken_Sid_AbsentWhenNoSession(t *testing.T) {
	storage := newSidTestStorage(t)

	authReqID := createTestAuthRequest(t, storage)
	req, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}

	assertSidAbsent(t, storage, req)
}

// TestBridge_Sid_ProtocolSession drives the REAL bridge + storage + resolver
// path: a genuine protocol-namespace session (the mxid_proto_sid cookie) backs
// the login, so the completed auth request carries `sid` == that session id.
func TestBridge_Sid_ProtocolSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	storage, sessions, rdb := newBridgeHarness(t)

	const protoSessID = "proto-sess-1"
	seedSession(t, rdb, protocolSessionKeyPrefix+protoSessID, &resolver.SSOSession{
		ID: protoSessID, UserID: 42, TenantID: 1, AuthType: "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	authReqID := createTestAuthRequest(t, storage)
	driveBridge(t, storage, sessions, authReqID, http.Cookie{Name: "mxid_proto_sid", Value: protoSessID})

	req := restoreAuthRequest(t, storage, authReqID)
	assertSidClaim(t, storage, req, protoSessID)
}

// TestBridge_Sid_PortalSessionAbsent is the Critical regression guard: a
// passwordless login (magic-link / SMS-OTP) creates ONLY a portal-namespace
// session — no protocol session. The bridge must still complete login (via the
// portal fallback) but must NOT emit that portal session id as `sid`, or WS2
// back-channel logout (which keys strictly on the protocol namespace) would
// never match it. Driven through the real bridge/storage/resolver path.
func TestBridge_Sid_PortalSessionAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	storage, sessions, rdb := newBridgeHarness(t)

	const portalSessID = "portal-sess-1"
	seedSession(t, rdb, portalSessionKeyPrefix+portalSessID, &resolver.SSOSession{
		ID: portalSessID, UserID: 42, TenantID: 1, AuthType: "magic_link",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	authReqID := createTestAuthRequest(t, storage)
	// Only the portal cookie is present — exactly what magic-link/SMS-OTP set.
	driveBridge(t, storage, sessions, authReqID, http.Cookie{Name: "mxid_portal_sid", Value: portalSessID})

	req := restoreAuthRequest(t, storage, authReqID)
	if sr, ok := req.(interface{ GetSessionID() string }); !ok || sr.GetSessionID() != "" {
		t.Fatalf("completed auth request must not carry a portal session id as sid, got %q", sr.GetSessionID())
	}
	assertSidAbsent(t, storage, req)
}

// TestBridge_Sid_StaleProtoCookieFallsBack covers the edge where a proto cookie
// is present but its protocol session no longer exists, while a live portal
// session does: login completes via the portal fallback and NO sid is emitted
// (the stale proto id is not resurrected as sid).
func TestBridge_Sid_StaleProtoCookieFallsBack(t *testing.T) {
	gin.SetMode(gin.TestMode)
	storage, sessions, rdb := newBridgeHarness(t)

	const portalSessID = "portal-sess-2"
	seedSession(t, rdb, portalSessionKeyPrefix+portalSessID, &resolver.SSOSession{
		ID: portalSessID, UserID: 42, TenantID: 1, AuthType: "sms_otp",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	authReqID := createTestAuthRequest(t, storage)
	driveBridge(t, storage, sessions, authReqID,
		http.Cookie{Name: "mxid_proto_sid", Value: "does-not-exist"}, // stale/no protocol session
		http.Cookie{Name: "mxid_portal_sid", Value: portalSessID},
	)

	req := restoreAuthRequest(t, storage, authReqID)
	assertSidAbsent(t, storage, req)
}

// TestRefreshToken_Sid_Persisted proves the Important fix: `sid` is carried on
// the refresh token record and survives rotation, so id_tokens reissued via
// the refresh_token grant keep the same `sid` the first login emitted (rather
// than silently dropping it on the second and subsequent tokens).
func TestRefreshToken_Sid_Persisted(t *testing.T) {
	storage := newSidTestStorage(t)
	ctx := context.Background()

	authReqID := createTestAuthRequest(t, storage)
	const protoSID = "proto-sid-refresh"
	if err := storage.AuthRequestDone(ctx, authReqID, "42", time.Now(), []string{"pwd"}, protoSID); err != nil {
		t.Fatalf("AuthRequestDone: %v", err)
	}
	authReq := restoreAuthRequest(t, storage, authReqID)

	// Code flow: mint the first access + refresh pair from the auth request.
	_, refreshTok, _, err := storage.CreateAccessAndRefreshTokens(ctx, authReq, "")
	if err != nil {
		t.Fatalf("CreateAccessAndRefreshTokens (code flow): %v", err)
	}

	// The refresh_token grant hands op a *refreshTokenRequest; its id_token
	// must still carry the original sid.
	rtReq, err := storage.TokenRequestByRefreshToken(ctx, refreshTok)
	if err != nil {
		t.Fatalf("TokenRequestByRefreshToken: %v", err)
	}
	assertSidClaim(t, storage, rtReq, protoSID)

	// Rotate the refresh token; sid must survive the rotation.
	_, rotatedTok, _, err := storage.CreateAccessAndRefreshTokens(ctx, rtReq, refreshTok)
	if err != nil {
		t.Fatalf("CreateAccessAndRefreshTokens (rotation): %v", err)
	}
	rotatedReq, err := storage.TokenRequestByRefreshToken(ctx, rotatedTok)
	if err != nil {
		t.Fatalf("TokenRequestByRefreshToken (rotated): %v", err)
	}
	assertSidClaim(t, storage, rotatedReq, protoSID)
}

// --- helpers -----------------------------------------------------------------

// The resolver / session.Manager namespace key prefixes. Mirrored here (rather
// than imported — they are unexported) so the test seeds sessions at the exact
// keys the real resolver reads.
const (
	protocolSessionKeyPrefix = "mxid:session:protocol:"
	portalSessionKeyPrefix   = "mxid:session:portal:"
)

func newSidTestStorage(t *testing.T) *Storage {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig())
}

func newBridgeHarness(t *testing.T) (*Storage, resolver.SessionResolver, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig()), resolver.NewSessionResolver(rdb), rdb
}

func createTestAuthRequest(t *testing.T, storage *Storage) string {
	t.Helper()
	req, err := storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     "app1",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	return req.GetID()
}

func restoreAuthRequest(t *testing.T, storage *Storage, authReqID string) op.AuthRequest {
	t.Helper()
	req, err := storage.AuthRequestByID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	return req
}

func seedSession(t *testing.T, rdb *redis.Client, key string, sess *resolver.SSOSession) {
	t.Helper()
	data, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := rdb.Set(context.Background(), key, data, time.Hour).Err(); err != nil {
		t.Fatalf("seed session %q: %v", key, err)
	}
}

// driveBridge runs a real LoginBridge.Handle for a first-party, no-consent app
// with the given cookies, asserting login completes (302 to the op callback).
func driveBridge(t *testing.T, storage *Storage, sessions resolver.SessionResolver, authReqID string, cookies ...http.Cookie) {
	t.Helper()
	apps := &fakeBridgeAppResolver{app: &resolver.AppConfig{
		ID: 1, ClientID: "app1", Protocol: "oidc", Status: 1,
		FirstParty: true, RequireConsent: false,
	}}
	bridge := NewLoginBridge(storage, apps, sessions, nil, nil, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	for i := range cookies {
		httpReq.AddCookie(&cookies[i])
	}
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusFound {
		t.Fatalf("bridge.Handle status = %d, want %d (body: %q)", w.Code, http.StatusFound, w.Body.String())
	}
}

// assertSidClaim runs the exact op hook that assembles id_token claims and
// asserts `sid` == want.
func assertSidClaim(t *testing.T, storage *Storage, req op.IDTokenRequest, want string) {
	t.Helper()
	userinfo := new(oidc.UserInfo)
	if err := storage.SetUserinfoFromRequest(context.Background(), userinfo, req, req.GetScopes()); err != nil {
		t.Fatalf("SetUserinfoFromRequest: %v", err)
	}
	if got := userinfo.Claims["sid"]; got != want {
		t.Fatalf(`id_token claims["sid"] = %v, want %q`, got, want)
	}
}

func assertSidAbsent(t *testing.T, storage *Storage, req op.IDTokenRequest) {
	t.Helper()
	userinfo := new(oidc.UserInfo)
	if err := storage.SetUserinfoFromRequest(context.Background(), userinfo, req, req.GetScopes()); err != nil {
		t.Fatalf("SetUserinfoFromRequest: %v", err)
	}
	if got, ok := userinfo.Claims["sid"]; ok {
		t.Fatalf(`expected no "sid" claim, got %v`, got)
	}
}

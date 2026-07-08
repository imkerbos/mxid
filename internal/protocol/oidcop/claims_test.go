package oidcop

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// --- fakes -------------------------------------------------------------------

// fakeClaimsIdentity resolves a single fixed user. ResolveClaims mirrors
// resolver.identityResolverImpl's shape closely enough for these tests: `sub`
// defaults to the raw snowflake id, `preferred_username` appears only under
// the profile scope — both are expected to be overridden by the subject
// strategy layer under test.
type fakeClaimsIdentity struct {
	resolver.IdentityResolver
	info *resolver.IdentityInfo
}

func (f *fakeClaimsIdentity) ResolveUser(_ context.Context, _ int64) (*resolver.IdentityInfo, error) {
	return f.info, nil
}

func (f *fakeClaimsIdentity) ResolveClaims(_ context.Context, _ int64, scopes []string) (map[string]any, error) {
	claims := map[string]any{"sub": strconv.FormatInt(f.info.ID, 10)}
	for _, sc := range scopes {
		if sc == "profile" {
			claims["preferred_username"] = f.info.Username
		}
	}
	return claims, nil
}

type fakeClaimsApps struct {
	resolver.AppResolver
	app *resolver.AppConfig
}

func (f *fakeClaimsApps) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return f.app, nil
}

type fakeClaimsTenants struct{ code string }

func (f *fakeClaimsTenants) GetTenantCode(_ context.Context, _ int64) (string, error) {
	return f.code, nil
}

type fakeClaimsAppRoles struct{ roles []string }

func (f *fakeClaimsAppRoles) ResolveAppRoles(_ context.Context, _, _, _ int64) ([]string, error) {
	return f.roles, nil
}

// --- app_roles -----------------------------------------------------------

// TestClaims_AppRoles_Userinfo proves the `app_roles` claim — the roles the
// approle adapter resolves for (user, app, tenant) — lands in the /userinfo
// response, mirroring internal/protocol/oidc/handler.go:1021-1029.
func TestClaims_AppRoles_Userinfo(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1"}},
		nil,
		&fakeClaimsAppRoles{roles: []string{"admin", "viewer"}},
	)

	info := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	got, _ := info.Claims["app_roles"].([]string)
	if len(got) != 2 || got[0] != "admin" || got[1] != "viewer" {
		t.Fatalf("userinfo app_roles = %v, want [admin viewer]", info.Claims["app_roles"])
	}
}

// TestClaims_AppRoles_IDToken proves the SAME `app_roles` claim reaches the
// id_token via Storage.SetUserinfoFromRequest — the op.CanSetUserinfoFromRequest
// hook zitadel/oidc's CreateIDToken calls while assembling id_token claims
// (pkg/op/token.go). Drives the real Storage/authRequest round-trip, exactly
// as sid_test.go does for `sid`.
func TestClaims_AppRoles_IDToken(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1"}},
		nil,
		&fakeClaimsAppRoles{roles: []string{"admin", "viewer"}},
	)
	storage := newClaimsTestStorage(t, store)
	ctx := context.Background()

	authReqID := createTestAuthRequest(t, storage)
	if err := storage.AuthRequestDone(ctx, authReqID, "42", time.Now(), []string{"pwd"}, ""); err != nil {
		t.Fatalf("AuthRequestDone: %v", err)
	}
	req, err := storage.AuthRequestByID(ctx, authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}

	userinfo := new(oidc.UserInfo)
	if err := storage.SetUserinfoFromRequest(ctx, userinfo, req, []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfoFromRequest: %v", err)
	}
	got, _ := userinfo.Claims["app_roles"].([]string)
	if len(got) != 2 || got[0] != "admin" || got[1] != "viewer" {
		t.Fatalf("id_token app_roles = %v, want [admin viewer]", userinfo.Claims["app_roles"])
	}
}

// TestClaims_AppRoles_AbsentWhenEmpty proves no `app_roles` claim is emitted
// when the adapter returns no roles for this (user, app) — matches the
// hand-rolled engine's `len(roleCodes) > 0` guard (handler.go:705).
func TestClaims_AppRoles_AbsentWhenEmpty(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1"}},
		nil,
		&fakeClaimsAppRoles{roles: nil},
	)
	info := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	if _, ok := info.Claims["app_roles"]; ok {
		t.Fatalf("expected no app_roles claim, got %v", info.Claims["app_roles"])
	}
}

// --- subject strategy ------------------------------------------------------

// TestClaims_SubjectStrategy_Pairwise proves `sub` for a pairwise-configured
// app is NOT the raw user id and is stable across calls for the same
// (client, user) — OIDC Core §8.1 pairwise pseudonymous identifiers, ported
// from internal/protocol/resolver.ResolveSubject via
// internal/protocol/oidc/handler.go:149-174's resolveSubject.
func TestClaims_SubjectStrategy_Pairwise(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1", SubjectStrategy: resolver.StrategyPairwise}},
		nil,
		nil,
	)

	info1 := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info1, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	if info1.Subject == "42" || info1.Subject == "" {
		t.Fatalf("pairwise sub = %q, want an opaque non-raw-id value", info1.Subject)
	}

	info2 := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info2, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo (2nd call): %v", err)
	}
	if info2.Subject != info1.Subject {
		t.Fatalf("pairwise sub not stable: %q != %q", info2.Subject, info1.Subject)
	}
}

// TestClaims_SubjectStrategy_PersistentID proves `persistent_id` yields the
// raw snowflake id as `sub`, and — combined with the pairwise test above —
// that different strategies genuinely diverge.
func TestClaims_SubjectStrategy_PersistentID(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1", SubjectStrategy: resolver.StrategyPersistentID}},
		nil,
		nil,
	)
	info := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	if info.Subject != "42" {
		t.Fatalf("persistent_id sub = %q, want %q", info.Subject, "42")
	}
}

// TestClaims_SubjectStrategy_ConsistentAcrossIDTokenAndUserinfo proves the
// pairwise sub computed for /userinfo is IDENTICAL to the one that lands in
// the id_token via SetUserinfoFromRequest — a divergent sub between the two
// breaks RP identity matching.
func TestClaims_SubjectStrategy_ConsistentAcrossIDTokenAndUserinfo(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1", SubjectStrategy: resolver.StrategyPairwise}},
		nil,
		nil,
	)
	storage := newClaimsTestStorage(t, store)
	ctx := context.Background()

	authReqID := createTestAuthRequest(t, storage)
	if err := storage.AuthRequestDone(ctx, authReqID, "42", time.Now(), []string{"pwd"}, ""); err != nil {
		t.Fatalf("AuthRequestDone: %v", err)
	}
	req, err := storage.AuthRequestByID(ctx, authReqID)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}

	idTokenInfo := new(oidc.UserInfo)
	if err := storage.SetUserinfoFromRequest(ctx, idTokenInfo, req, []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfoFromRequest: %v", err)
	}

	userinfoInfo := new(oidc.UserInfo)
	if err := store.SetUserinfo(ctx, userinfoInfo, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}

	if idTokenInfo.Subject == "" || idTokenInfo.Subject == "42" {
		t.Fatalf("id_token sub = %q, want an opaque pairwise value", idTokenInfo.Subject)
	}
	if idTokenInfo.Subject != userinfoInfo.Subject {
		t.Fatalf("sub diverges between id_token (%q) and userinfo (%q)", idTokenInfo.Subject, userinfoInfo.Subject)
	}
}

// --- tenant_code + preferred_username --------------------------------------

// TestClaims_TenantCodeAndPreferredUsername proves both claims are emitted:
// tenant_code from the TenantResolver, preferred_username as the strategy's
// display form (username_suffixed overrides it to "user@tenant"), overriding
// whatever the bare profile-scope preferred_username would have been.
func TestClaims_TenantCodeAndPreferredUsername(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1", SubjectStrategy: resolver.StrategyUsernameSuffixed}},
		&fakeClaimsTenants{code: "acme"},
		nil,
	)
	info := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info, "42", "app1", []string{"openid", "profile"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	if got := info.Claims["tenant_code"]; got != "acme" {
		t.Fatalf("tenant_code = %v, want %q", got, "acme")
	}
	if got := info.Claims["preferred_username"]; got != "alice@acme" {
		t.Fatalf("preferred_username = %v, want %q", got, "alice@acme")
	}
}

// TestClaims_TenantCode_AbsentWhenUnresolved proves no tenant_code claim
// leaks through when the TenantResolver is not wired (nil) — nil-safety per
// the WS5 brief's "pass tenantID explicitly / nil-safe adapters" contract.
func TestClaims_TenantCode_AbsentWhenUnresolved(t *testing.T) {
	store := NewClaimsStore(
		&fakeClaimsIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"}},
		&fakeClaimsApps{app: &resolver.AppConfig{ID: 100, ClientID: "app1"}},
		nil,
		nil,
	)
	info := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	if _, ok := info.Claims["tenant_code"]; ok {
		t.Fatalf("expected no tenant_code claim, got %v", info.Claims["tenant_code"])
	}
}

// --- helpers -----------------------------------------------------------------

// newClaimsTestStorage wires a real Storage (Redis-backed auth requests) with
// the given ClaimsStore as its ClaimsResolver, so SetUserinfoFromRequest
// exercises the exact delegation path production uses.
func newClaimsTestStorage(t *testing.T, claims ClaimsResolver) *Storage {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewStorage(rdb, nil, nil, claims, nil, nil, DefaultConfig())
}

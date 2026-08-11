package oidcop

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// The three tests in id_token_userinfo_claims_test.go pin our side of the
// contract: the flag is parsed and returned. They cannot see the part that
// actually delivers the feature, which lives in the dependency —
// op.CreateIDToken consults Client.IDTokenUserinfoClaimsAssertion and, when it
// is false, strips profile/email/phone/address from the scopes it hands to
// SetUserinfoFromScopes (zitadel/oidc pkg/op/token.go). A library upgrade that
// moved, renamed or re-gated that call would leave all three green while
// Confluence silently went back to failing.
//
// So this test drives the real op.CreateIDToken against a storage that records
// which scopes survived, and asserts the gate both ways.
//
// It also pins the second half of that condition, which is easy to miss: the
// stripping only happens when an access token is present. An id_token minted
// without one keeps its scopes regardless of the flag.

// idTokenGateStorage implements only the handful of op.Storage methods
// CreateIDToken reaches. The embedded nil interface makes any other call panic
// with a clear nil-dereference rather than silently returning a zero value.
type idTokenGateStorage struct {
	op.Storage

	key       *rsa.PrivateKey
	gotScopes []string
}

func (s *idTokenGateStorage) SigningKey(context.Context) (op.SigningKey, error) {
	return idTokenGateSigningKey{key: s.key}, nil
}

func (s *idTokenGateStorage) SetUserinfoFromScopes(_ context.Context, info *oidc.UserInfo, _, _ string, scopes []string) error {
	s.gotScopes = scopes
	// Mirror what the real storage does for the email scope, so the assertion
	// below can be about an actual claim rather than only about scopes.
	if slices.Contains(scopes, "email") {
		info.Email = "layne@example.com"
	}
	return nil
}

type idTokenGateSigningKey struct{ key *rsa.PrivateKey }

func (k idTokenGateSigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k idTokenGateSigningKey) Key() any                                    { return k.key }
func (k idTokenGateSigningKey) ID() string                                  { return "test-key" }

// idTokenGateRequest is a minimal op.IDTokenRequest.
type idTokenGateRequest struct{}

func (idTokenGateRequest) GetAMR() []string      { return []string{"pwd"} }
func (idTokenGateRequest) GetAudience() []string { return []string{"c1"} }
func (idTokenGateRequest) GetAuthTime() time.Time {
	return time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
}
func (idTokenGateRequest) GetClientID() string { return "c1" }
func (idTokenGateRequest) GetScopes() []string {
	return []string{"openid", "profile", "email", "phone"}
}
func (idTokenGateRequest) GetSubject() string { return "42" }

func mintIDToken(t *testing.T, protocolConfig, accessToken string) (*idTokenGateStorage, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	storage := &idTokenGateStorage{key: key}
	tok, err := op.CreateIDToken(
		context.Background(),
		"https://mxid.example.com/protocol/oidc",
		idTokenGateRequest{},
		time.Hour,
		accessToken,
		"", // code
		storage,
		clientFor(t, protocolConfig),
	)
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}
	return storage, tok
}

func TestCreateIDToken_StripsUserinfoScopes_WhenFlagOff(t *testing.T) {
	storage, tok := mintIDToken(t, `{}`, "an-access-token")

	for _, scope := range []string{"profile", "email", "phone"} {
		if slices.Contains(storage.gotScopes, scope) {
			t.Fatalf("scope %q reached SetUserinfoFromScopes with the flag off; "+
				"the id_token would carry identity claims the app never asked for (scopes=%v)",
				scope, storage.gotScopes)
		}
	}
	if !slices.Contains(storage.gotScopes, "openid") {
		t.Fatalf("openid must survive; got %v", storage.gotScopes)
	}
	assertEmailClaim(t, tok, false)
}

func TestCreateIDToken_KeepsUserinfoScopes_WhenFlagOn(t *testing.T) {
	storage, tok := mintIDToken(t, `{"id_token_userinfo_claims":true}`, "an-access-token")

	for _, scope := range []string{"openid", "profile", "email", "phone"} {
		if !slices.Contains(storage.gotScopes, scope) {
			t.Fatalf("scope %q was stripped even though the app enabled "+
				"id_token_userinfo_claims; Confluence-style relying parties would still "+
				"fail with \"Claim [email] could not be found\" (scopes=%v)",
				scope, storage.gotScopes)
		}
	}
	assertEmailClaim(t, tok, true)
}

// TestCreateIDToken_NoAccessToken_KeepsScopes pins the other half of zitadel's
// condition. The strip is inside `if accessToken != ""`, so the implicit-style
// path that mints an id_token alone is unaffected by the flag. Documented here
// because it looks like an inconsistency until you read the library.
func TestCreateIDToken_NoAccessToken_KeepsScopes(t *testing.T) {
	storage, _ := mintIDToken(t, `{}`, "")

	if !slices.Contains(storage.gotScopes, "email") {
		t.Fatalf("with no access token zitadel does not strip userinfo scopes, "+
			"regardless of the flag; got %v", storage.gotScopes)
	}
}

func assertEmailClaim(t *testing.T, rawIDToken string, want bool) {
	t.Helper()
	sig, err := jose.ParseSigned(rawIDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	payload := sig.UnsafePayloadWithoutVerification()
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	_, got := claims["email"]
	if got != want {
		t.Fatalf("id_token email claim present = %v, want %v (claims=%v)", got, want, claims)
	}
}

package oidclogout

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// fakeKeySource is a provider-keyset test double: it hands back a fixed RSA
// key/kid/alg instead of hitting the DB-backed oidckey.Service, so the signer
// can be exercised without a database.
type fakeKeySource struct {
	priv *rsa.PrivateKey
	kid  string
	alg  string
}

func (f *fakeKeySource) LoadActiveSigningKey(_ context.Context) (*rsa.PrivateKey, string, string, error) {
	return f.priv, f.kid, f.alg, nil
}

func newFakeKeySource(t *testing.T) *fakeKeySource {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &fakeKeySource{priv: priv, kid: "active-kid-1", alg: "RS256"}
}

// TestSignLogoutToken_ClaimsAndHeader asserts the signed JWT carries the
// spec-required shape: typ=logout+jwt header, kid from the active provider
// key, iss/aud/sub claims, the back-channel-logout events marker, and NO sid
// when the caller didn't request one.
func TestSignLogoutToken_ClaimsAndHeader(t *testing.T) {
	ks := newFakeKeySource(t)
	signer := NewProviderKeysetSigner(ks)

	claims := LogoutTokenClaims{
		Issuer:   "https://sso.example.com/protocol/oidc",
		Audience: "client-a",
		Subject:  "5001",
	}

	signed, err := signer.SignLogoutToken(context.Background(), claims)
	if err != nil {
		t.Fatalf("SignLogoutToken: %v", err)
	}

	tok, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) {
		return &ks.priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parse signed token: %v", err)
	}

	if got := tok.Header["typ"]; got != "logout+jwt" {
		t.Errorf("typ header = %v, want logout+jwt", got)
	}
	if got := tok.Header["kid"]; got != ks.kid {
		t.Errorf("kid header = %v, want %v", got, ks.kid)
	}

	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T, want jwt.MapClaims", tok.Claims)
	}
	if mc["iss"] != claims.Issuer {
		t.Errorf("iss = %v, want %v", mc["iss"], claims.Issuer)
	}
	if mc["aud"] != claims.Audience {
		t.Errorf("aud = %v, want %v", mc["aud"], claims.Audience)
	}
	if mc["sub"] != claims.Subject {
		t.Errorf("sub = %v, want %v", mc["sub"], claims.Subject)
	}
	if mc["iat"] == nil {
		t.Error("iat missing")
	}
	if mc["jti"] == nil || mc["jti"] == "" {
		t.Error("jti missing/empty")
	}
	events, ok := mc["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim type = %T, want map[string]any", mc["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Error("events missing backchannel-logout marker")
	}
	if _, present := mc["sid"]; present {
		t.Errorf("sid claim present = %v, want absent when Claims.SID is empty", mc["sid"])
	}
}

// TestSignLogoutToken_WithSID asserts the sid claim is emitted when the
// caller sets LogoutTokenClaims.SID (backchannel_logout_session_required).
func TestSignLogoutToken_WithSID(t *testing.T) {
	ks := newFakeKeySource(t)
	signer := NewProviderKeysetSigner(ks)

	claims := LogoutTokenClaims{
		Issuer:   "https://sso.example.com/protocol/oidc",
		Audience: "client-a",
		Subject:  "5001",
		SID:      "proto-sess-1",
	}

	signed, err := signer.SignLogoutToken(context.Background(), claims)
	if err != nil {
		t.Fatalf("SignLogoutToken: %v", err)
	}

	tok, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	mc := tok.Claims.(jwt.MapClaims)
	if mc["sid"] != "proto-sess-1" {
		t.Errorf("sid = %v, want proto-sess-1", mc["sid"])
	}
}

// TestSignLogoutToken_KeySourceError propagates the key-load error rather
// than silently signing with a zero key.
func TestSignLogoutToken_KeySourceError(t *testing.T) {
	signer := NewProviderKeysetSigner(erroringKeySource{})
	_, err := signer.SignLogoutToken(context.Background(), LogoutTokenClaims{
		Issuer: "https://sso.example.com/protocol/oidc", Audience: "a", Subject: "1",
	})
	if err == nil {
		t.Fatal("SignLogoutToken with erroring key source: want error, got nil")
	}
}

type erroringKeySource struct{}

func (erroringKeySource) LoadActiveSigningKey(_ context.Context) (*rsa.PrivateKey, string, string, error) {
	return nil, "", "", errKeySourceFailed
}

var errKeySourceFailed = &keySourceError{"key source unavailable"}

type keySourceError struct{ msg string }

func (e *keySourceError) Error() string { return e.msg }

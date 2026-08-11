package oidcop

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// zitadel demands PKCE only for public clients (auth method "none"). An app
// that set `pkce_required` in its protocol config got nothing: the key was
// parsed into clientConfig and then read by no code at all, so the console
// reported a saved setting that never took effect.
//
// These tests pin the enforcement to the authorization entry point, including
// the downgrade to the "plain" challenge method, which is what makes PKCE
// worth requiring in the first place.

// pkceClientResolver serves one client to Storage.enforcePKCE.
type pkceClientResolver struct {
	client op.Client
	err    error
}

func (r pkceClientResolver) ClientByID(context.Context, string) (op.Client, error) {
	return r.client, r.err
}
func (r pkceClientResolver) AuthorizeSecret(context.Context, string, string) error { return nil }
func (r pkceClientResolver) ClientKey(context.Context, string, string) (*jose.JSONWebKey, error) {
	panic("not used")
}

func storageWithClient(t *testing.T, protocolConfig string) *Storage {
	t.Helper()
	s := newSidTestStorage(t)
	s.clients = pkceClientResolver{client: clientFor(t, protocolConfig)}
	return s
}

func authReq(challenge string, method oidc.CodeChallengeMethod) *oidc.AuthRequest {
	return &oidc.AuthRequest{
		ClientID:            "c1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		ResponseType:        oidc.ResponseTypeCode,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
	}
}

func TestCreateAuthRequest_PKCERequired_RejectsMissingChallenge(t *testing.T) {
	s := storageWithClient(t, `{"pkce_required":true}`)

	_, err := s.CreateAuthRequest(context.Background(), authReq("", ""), "")
	if err == nil {
		t.Fatal("an app configured with pkce_required accepted an authorization request with no code_challenge; the setting is inert again")
	}
	if !strings.Contains(err.Error(), "code_challenge") {
		t.Fatalf("error should name the missing parameter, got %v", err)
	}
}

func TestCreateAuthRequest_PKCERequired_RejectsPlainMethod(t *testing.T) {
	s := storageWithClient(t, `{"pkce_required":true}`)

	_, err := s.CreateAuthRequest(context.Background(), authReq("abc", oidc.CodeChallengeMethodPlain), "")
	if err == nil {
		t.Fatal("plain code_challenge_method accepted; a challenge sent in the clear gives none of PKCE's protection")
	}
	if !strings.Contains(err.Error(), "S256") {
		t.Fatalf("error should name the required method, got %v", err)
	}
}

func TestCreateAuthRequest_PKCERequired_AcceptsS256(t *testing.T) {
	s := storageWithClient(t, `{"pkce_required":true}`)

	if _, err := s.CreateAuthRequest(context.Background(), authReq("abc", oidc.CodeChallengeMethodS256), ""); err != nil {
		t.Fatalf("a correct PKCE request must be accepted: %v", err)
	}
}

// TestCreateAuthRequest_PKCENotRequired_LeavesRequestsAlone proves the gate is
// opt-in. Every existing app has no pkce_required key, and none of them may
// start failing because this enforcement was added.
func TestCreateAuthRequest_PKCENotRequired_LeavesRequestsAlone(t *testing.T) {
	for name, cfg := range map[string]string{
		"empty config":   `{}`,
		"explicit false": `{"pkce_required":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := storageWithClient(t, cfg)
			if _, err := s.CreateAuthRequest(context.Background(), authReq("", ""), ""); err != nil {
				t.Fatalf("an app that never asked for PKCE must keep working: %v", err)
			}
		})
	}
}

// TestEnforcePKCE_FailsOpenWithoutAResolver keeps the hook from becoming a
// second, divergent client-validation gate: when the client cannot be resolved
// the library's own validation is what rejects the request.
func TestEnforcePKCE_FailsOpenWithoutAResolver(t *testing.T) {
	s := newSidTestStorage(t) // no client resolver wired
	if err := s.enforcePKCE(context.Background(), authReq("", "")); err != nil {
		t.Fatalf("must not reject when no client resolver is available: %v", err)
	}

	s.clients = pkceClientResolver{err: errors.New("client not found")}
	if err := s.enforcePKCE(context.Background(), authReq("", "")); err != nil {
		t.Fatalf("must not reject when the client cannot be resolved: %v", err)
	}
}

package oidcop

import (
	"context"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// Compile-time assertion that Storage implements op.ClientCredentialsStorage.
// zitadel/oidc auto-detects this via a type assertion on the Storage passed
// to NewProvider (see op.Provider.GrantTypeClientCredentialsSupported) — no
// separate Config flag is needed to turn the grant on, unlike
// GrantTypeRefreshToken.
var _ op.ClientCredentialsStorage = (*Storage)(nil)

// ClientCredentials authenticates a client for the OAuth 2.0
// client_credentials (machine-to-machine) grant. Confidential-only,
// fail-closed: a public client (spa/native — op.ApplicationType != Web) MUST
// NOT obtain a token via this grant, matching the hand-rolled engine's
// tokenClientCredentials (internal/protocol/oidc/handler.go:934), which
// rejects isPublicClient(app) up front. op.IsConfidentialType mirrors that
// same ClientType-derived check via oidcClient.ApplicationType() (client.go).
func (s *Storage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	client, err := s.clients.ClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !op.IsConfidentialType(client) {
		return nil, fmt.Errorf("client_credentials grant requires a confidential client")
	}
	if err := s.clients.AuthorizeSecret(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	return client, nil
}

// ClientCredentialsTokenRequest builds the TokenRequest for an authorized
// client_credentials grant. Requested scopes are filtered down to what the
// client is actually allowed (silently dropping the rest, mirroring
// op.ValidateAuthReqScopes' own DeleteFunc behavior for the authorize
// endpoint) rather than trusting the caller-supplied scope list verbatim —
// the hand-rolled engine's tokenClientCredentials does not scope-check at
// all; this closes that gap for the zitadel engine.
func (s *Storage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	client, err := s.clients.ClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if client.IsScopeAllowed(sc) {
			allowed = append(allowed, sc)
		}
	}
	return &clientCredentialsRequest{clientID: clientID, scopes: allowed}, nil
}

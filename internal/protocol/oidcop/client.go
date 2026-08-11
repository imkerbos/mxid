package oidcop

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// clientConfig is the OIDC slice of an app's protocol_config JSONB. Kept local
// to oidcop (a copy of the fields we need) so this package does not depend on
// the hand-rolled internal/protocol/oidc package that P7 retires.
type clientConfig struct {
	GrantTypes            []string      `json:"grant_types"`
	ResponseTypes         []string      `json:"response_types"`
	Scopes                []string      `json:"scopes"`
	PKCERequired          bool          `json:"pkce_required"`
	IDTokenTTL            int           `json:"id_token_ttl"`
	TokenEndpointAuthMode string        `json:"token_endpoint_auth_mode"`
	JWKS                  string        `json:"jwks"`
	JWKSURI               string        `json:"jwks_uri"`
	ClaimMappers          []claimMapper `json:"claim_mappers"`
	// IDTokenUserinfoClaims puts the identity claims (email, name, phone,
	// locale, …) into the id_token in addition to serving them from the
	// userinfo endpoint. Off by default because the spec prefers the smaller
	// token and every conformant RP can fetch userinfo.
	//
	// It exists because plenty of real relying parties never call userinfo:
	// Atlassian's Confluence OIDC plugin reads the id_token only, and its
	// just-in-time provisioning fails with "Claim [email] could not be found"
	// against an otherwise perfectly valid login. Such an RP has no setting to
	// fix on its side, so the IdP has to meet it where it is.
	//
	// Enable it per app rather than globally: it widens what a leaked id_token
	// discloses, so an app should only carry the extra claims when its RP
	// actually needs them.
	IDTokenUserinfoClaims bool `json:"id_token_userinfo_claims"`
	// RateLimitPerMin overrides the IdP-wide default token-endpoint rate limit
	// (see ratelimit.go's defaultTokenRateLimitPerMin) for this client. Same
	// field name/shape as the hand-rolled engine's oidc.Config.RateLimitPerMin
	// so a client's configured limit carries over unchanged across engines.
	RateLimitPerMin int `json:"rate_limit_per_min"`
}

// claimMapper is one declarative per-app claim projection (Keycloak "mapper" /
// Auth0 "rule" equivalent): emit Claim from the dotted identity Source, gated by
// Scope ("" or "*" = always).
type claimMapper struct {
	Claim  string `json:"claim"`
	Source string `json:"source"`
	Scope  string `json:"scope"`
}

// defaultIDTokenTTLSeconds is the fallback id_token lifetime (1 hour).
const defaultIDTokenTTLSeconds = 3600

func parseClientConfig(raw json.RawMessage) clientConfig {
	cfg := clientConfig{
		GrantTypes:            []string{"authorization_code", "refresh_token"},
		ResponseTypes:         []string{"code"},
		Scopes:                []string{"openid", "profile", "email"},
		IDTokenTTL:            defaultIDTokenTTLSeconds,
		TokenEndpointAuthMode: "client_secret_post",
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg)
	}
	return cfg
}

// oidcClient adapts a resolved MXID app into op.Client.
type oidcClient struct {
	app      *resolver.AppConfig
	cfg      clientConfig
	loginURL func(authRequestID string) string
}

var _ op.Client = (*oidcClient)(nil)

func (c *oidcClient) GetID() string             { return c.app.ClientID }
func (c *oidcClient) RedirectURIs() []string    { return c.app.RedirectURIs }
func (c *oidcClient) LoginURL(id string) string { return c.loginURL(id) }
func (c *oidcClient) DevMode() bool             { return false }
func (c *oidcClient) ClockSkew() time.Duration  { return 0 }

func (c *oidcClient) PostLogoutRedirectURIs() []string {
	if c.app.LogoutURL != "" {
		return []string{c.app.LogoutURL}
	}
	return nil
}

func (c *oidcClient) ApplicationType() op.ApplicationType {
	switch c.app.ClientType {
	case "spa":
		return op.ApplicationTypeUserAgent
	case "native":
		return op.ApplicationTypeNative
	default: // web_app, m2m
		return op.ApplicationTypeWeb
	}
}

func (c *oidcClient) AuthMethod() oidc.AuthMethod {
	switch c.cfg.TokenEndpointAuthMode {
	case "client_secret_basic":
		return oidc.AuthMethodBasic
	case "none":
		return oidc.AuthMethodNone
	case "private_key_jwt":
		return oidc.AuthMethodPrivateKeyJWT
	default: // client_secret_post, client_secret_jwt (bcrypt-stored → treated as post)
		return oidc.AuthMethodPost
	}
}

// ResponseTypes: WS6-B drops implicit per the OAuth 2.1 migration decision
// (hybrid is deferred, not built). This engine only ever offers the
// authorization code flow (+PKCE) — "code" is returned unconditionally,
// ignoring cfg.ResponseTypes, so a pre-migration app record (or a stray admin
// edit) storing "id_token"/"token id_token" in protocol_config cannot
// re-enable implicit purely through configuration. op's authorize validation
// (ValidateAuthReqResponseType) rejects any response_type not in this list.
func (c *oidcClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *oidcClient) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.cfg.GrantTypes))
	for _, gt := range c.cfg.GrantTypes {
		out = append(out, oidc.GrantType(gt))
	}
	return out
}

// AccessTokenTypeBearer (opaque) — revocable and introspectable via our Redis
// store, the correct choice for an SSO IdP (vs self-contained JWT access tokens
// that resource servers accept without a revocation check).
func (c *oidcClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }

func (c *oidcClient) IDTokenLifetime() time.Duration {
	if c.cfg.IDTokenTTL > 0 {
		return time.Duration(c.cfg.IDTokenTTL) * time.Second
	}
	return time.Hour
}

func (c *oidcClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *oidcClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed gates which scopes a client may request. Standard OIDC scopes
// are always permitted; anything else must be in the app's configured allowlist.
func (c *oidcClient) IsScopeAllowed(scope string) bool {
	switch scope {
	case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone,
		oidc.ScopeAddress, oidc.ScopeOfflineAccess:
		return true
	}
	return slices.Contains(c.cfg.Scopes, scope)
}

// PKCERequired reports whether this app refuses an authorization request that
// carries no code_challenge.
//
// zitadel only demands PKCE for public clients (auth method "none"). This is
// the per-app switch on top of that, so a confidential client can be held to
// the same bar — which is what OAuth 2.1 asks for. Not part of op.Client;
// Storage.CreateAuthRequest type-asserts for it.
//
// The `pkce_required` key was parsed into clientConfig for a long time and read
// by nothing, so an operator who set it got no enforcement and no warning.
func (c *oidcClient) PKCERequired() bool {
	return c.cfg.PKCERequired
}

// IDTokenUserinfoClaimsAssertion reports whether the identity claims should ride
// in the id_token as well as the userinfo endpoint. Default false: the spec
// prefers the smaller token, and a conformant RP fetches userinfo for the rest.
//
// Apps set `id_token_userinfo_claims: true` when their RP never calls userinfo —
// see the field's doc comment for why that is not a hypothetical.
func (c *oidcClient) IDTokenUserinfoClaimsAssertion() bool {
	return c.cfg.IDTokenUserinfoClaims
}

// --- ClientResolver ----------------------------------------------------------

// ClientStore resolves MXID apps as OIDC clients for the op.Storage.
type ClientStore struct {
	apps     resolver.AppResolver
	loginURL func(authRequestID string) string
}

var _ ClientResolver = (*ClientStore)(nil)

// NewClientStore wires a ClientStore. loginURL builds the BFF login redirect
// target carrying the authRequestID (the P6 bridge entrypoint).
func NewClientStore(apps resolver.AppResolver, loginURL func(authRequestID string) string) *ClientStore {
	return &ClientStore{apps: apps, loginURL: loginURL}
}

func (s *ClientStore) resolve(ctx context.Context, clientID string) (*oidcClient, error) {
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, oidc.ErrInvalidClient().WithParent(fmt.Errorf("client not found"))
	}
	if app.Protocol != "oidc" {
		return nil, oidc.ErrInvalidClient().WithParent(fmt.Errorf("app %s is not an OIDC client", clientID))
	}
	if app.Status != 1 {
		return nil, oidc.ErrInvalidClient().WithParent(fmt.Errorf("client %s is disabled", clientID))
	}
	return &oidcClient{app: app, cfg: parseClientConfig(app.ProtocolConfig), loginURL: s.loginURL}, nil
}

func (s *ClientStore) ClientByID(ctx context.Context, clientID string) (op.Client, error) {
	return s.resolve(ctx, clientID)
}

func (s *ClientStore) AuthorizeSecret(ctx context.Context, clientID, clientSecret string) error {
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if app == nil || app.ClientSecret == "" {
		return fmt.Errorf("invalid client credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(app.ClientSecret), []byte(clientSecret)); err != nil {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

// ClientKey returns a client's registered public JWK for private_key_jwt client
// authentication, matched by key id from the app's inline JWKS.
func (s *ClientStore) ClientKey(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("client not found")
	}
	cfg := parseClientConfig(app.ProtocolConfig)
	if cfg.JWKS == "" {
		return nil, fmt.Errorf("client %s has no registered JWKS", clientID)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(cfg.JWKS), &set); err != nil {
		return nil, fmt.Errorf("parse client JWKS: %w", err)
	}
	for i := range set.Keys {
		if set.Keys[i].KeyID == keyID {
			return &set.Keys[i], nil
		}
	}
	// No kid match: if exactly one key, use it (clients often omit kid).
	if len(set.Keys) == 1 {
		return &set.Keys[0], nil
	}
	return nil, fmt.Errorf("no matching key for kid %q", keyID)
}

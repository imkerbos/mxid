package oidcop

import (
	"encoding/json"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// The engine reads protocol_config with the OIDC registration metadata names.
// It used to read token_endpoint_auth_mode and id_token_ttl — close enough to
// the real token_endpoint_auth_method / id_token_lifetime to pass review,
// different enough that the value never arrived.
//
// The console writes "none" for every SPA and native client it creates. With
// the wrong key that value was invisible, the config fell through to the
// client_secret_post default, and the public client's token exchange was
// rejected with invalid_client — a correctly configured app that could not
// work, and no error pointing at the spelling.

func TestParseClientConfig_ReadsCanonicalKeys(t *testing.T) {
	raw := json.RawMessage(`{"token_endpoint_auth_method":"none","id_token_lifetime":1800}`)
	cfg := parseClientConfig(raw)

	if cfg.TokenEndpointAuthMode != "none" {
		t.Errorf("auth method = %q, want none — a public client read as confidential is rejected with invalid_client", cfg.TokenEndpointAuthMode)
	}
	if cfg.IDTokenTTL != 1800 {
		t.Errorf("id_token lifetime = %d, want 1800", cfg.IDTokenTTL)
	}
}

// Apps configured before the rename still carry the old spellings; their
// settings must survive.
func TestParseClientConfig_FallsBackToLegacyKeys(t *testing.T) {
	raw := json.RawMessage(`{"token_endpoint_auth_mode":"none","id_token_ttl":900}`)
	cfg := parseClientConfig(raw)

	if cfg.TokenEndpointAuthMode != "none" {
		t.Errorf("auth method = %q, want none from the legacy key", cfg.TokenEndpointAuthMode)
	}
	if cfg.IDTokenTTL != 900 {
		t.Errorf("id_token lifetime = %d, want 900 from the legacy key", cfg.IDTokenTTL)
	}
}

// An app carrying both keeps the canonical one; a stale legacy value must not
// override a current setting.
func TestParseClientConfig_CanonicalBeatsLegacy(t *testing.T) {
	raw := json.RawMessage(`{
		"token_endpoint_auth_method":"client_secret_basic","token_endpoint_auth_mode":"none",
		"id_token_lifetime":1800,"id_token_ttl":900}`)
	cfg := parseClientConfig(raw)

	if cfg.TokenEndpointAuthMode != "client_secret_basic" {
		t.Errorf("auth method = %q, want the canonical client_secret_basic", cfg.TokenEndpointAuthMode)
	}
	if cfg.IDTokenTTL != 1800 {
		t.Errorf("id_token lifetime = %d, want the canonical 1800", cfg.IDTokenTTL)
	}
}

func TestParseClientConfig_DefaultsWhenAbsent(t *testing.T) {
	cfg := parseClientConfig(json.RawMessage(`{"scopes":["openid"]}`))

	if cfg.TokenEndpointAuthMode != "client_secret_post" {
		t.Errorf("auth method = %q, want the client_secret_post default", cfg.TokenEndpointAuthMode)
	}
	if cfg.IDTokenTTL != defaultIDTokenTTLSeconds {
		t.Errorf("id_token lifetime = %d, want the default %d", cfg.IDTokenTTL, defaultIDTokenTTLSeconds)
	}
}

// The whole point: what the console writes for an SPA has to reach AuthMethod,
// because that is what decides whether a client secret is demanded.
func TestAuthMethod_PublicClientFromConsoleDefaults(t *testing.T) {
	// Byte-for-byte the protocol_config the console creates for client_type=spa.
	raw := json.RawMessage(`{
		"scopes":["openid","profile","email","groups"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"pkce_required":true,
		"access_token_lifetime":3600,
		"id_token_lifetime":3600,
		"refresh_token_lifetime":2592000,
		"id_token_signing_alg":"RS256",
		"subject_type":"public"}`)

	c := &oidcClient{cfg: parseClientConfig(raw)}
	if got := c.AuthMethod(); got != oidc.AuthMethodNone {
		t.Fatalf("AuthMethod() = %q, want none: an SPA created through the console cannot exchange its code otherwise", got)
	}
}

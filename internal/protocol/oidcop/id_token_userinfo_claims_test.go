package oidcop

import (
	"encoding/json"
	"testing"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// The identity claims (email, name, phone, locale) are served from the userinfo
// endpoint and, by default, kept out of the id_token. That default is right for
// a conformant relying party, but several real ones never call userinfo at all:
// Atlassian's Confluence OIDC plugin reads the id_token only, and its
// just-in-time provisioning dies with "Claim [email] could not be found" on a
// login that otherwise succeeded end to end.
//
// zitadel decides this per client, through IDTokenUserinfoClaimsAssertion. That
// method used to return a hardcoded false, so no app configuration could reach
// it — including claim_mappers, which are assembled correctly and then dropped
// at the same gate. These tests pin the flag to the app's protocol_config so the
// hardcoding cannot come back, and so an app that does not ask for it keeps the
// smaller token.

func clientFor(t *testing.T, protocolConfig string) *oidcClient {
	t.Helper()
	app := &resolver.AppConfig{
		ClientID:       "c1",
		Protocol:       "oidc",
		ProtocolConfig: json.RawMessage(protocolConfig),
	}
	return &oidcClient{app: app, cfg: parseClientConfig(app.ProtocolConfig)}
}

func TestIDTokenUserinfoClaimsAssertion_DefaultsOff(t *testing.T) {
	for name, cfg := range map[string]string{
		"empty config":     `{}`,
		"unrelated config": `{"scopes":["openid","email"],"pkce_required":true}`,
		"explicit false":   `{"id_token_userinfo_claims":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := clientFor(t, cfg).IDTokenUserinfoClaimsAssertion(); got {
				t.Fatalf("an app that never asked for identity claims in its id_token must not get them; got %v", got)
			}
		})
	}
}

func TestIDTokenUserinfoClaimsAssertion_HonoursTheAppSetting(t *testing.T) {
	c := clientFor(t, `{"id_token_userinfo_claims":true}`)
	if !c.IDTokenUserinfoClaimsAssertion() {
		t.Fatal("app set id_token_userinfo_claims=true but the client still refuses to assert userinfo claims " +
			"into the id_token — this is the hardcoded-false regression that broke Confluence JIT provisioning")
	}
}

// The flag has to survive alongside the rest of the OIDC config, since the app
// that needs it will already carry redirect URIs, scopes and often claim
// mappers. A parse that silently loses it would look exactly like the bug.
func TestIDTokenUserinfoClaims_ParsesAlongsideOtherSettings(t *testing.T) {
	c := clientFor(t, `{
		"grant_types":["authorization_code"],
		"response_types":["code"],
		"scopes":["openid","profile","email"],
		"id_token_userinfo_claims":true,
		"claim_mappers":[{"claim":"email","source":"user.email","scope":"email"}],
		"id_token_ttl":600
	}`)
	if !c.IDTokenUserinfoClaimsAssertion() {
		t.Fatal("id_token_userinfo_claims was lost while parsing a fully-populated protocol_config")
	}
	if got := c.cfg.IDTokenTTL; got != 600 {
		t.Fatalf("neighbouring settings must survive too: id_token_ttl = %d, want 600", got)
	}
	if got := len(c.cfg.ClaimMappers); got != 1 {
		t.Fatalf("neighbouring settings must survive too: %d claim mappers, want 1", got)
	}
}

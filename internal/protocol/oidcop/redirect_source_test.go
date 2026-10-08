package oidcop

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// The redirect_uri allow-list has exactly ONE source of truth: the mxid_app
// redirect_uris COLUMN, surfaced as resolver.AppConfig.RedirectURIs. A
// redirect_uris key inside protocol_config is dead weight — nothing writes it
// (the console and the onboarding templates both target the column) and
// nothing may read it.
//
// This is pinned in a test because the two can disagree, and reading the wrong
// one yields a confident but wrong answer to "what callbacks does this app
// accept?" — a question asked exactly when it matters most.
//
// Exact matching against the registered value (RFC 6749 §3.1.2) is the control
// that keeps an unregistered callback from ever receiving a code. A future
// change that "helpfully" merged or fell back to the protocol_config copy would
// widen the list with stale URLs, silently, on the one check doing that work.

type redirSrcApps struct {
	resolver.AppResolver
	app *resolver.AppConfig
}

func (f *redirSrcApps) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return f.app, nil
}

func TestRedirectURIsComeFromColumnNotProtocolConfig(t *testing.T) {
	const enforced = "https://app.example.com/callback"
	const stale = "https://retired.example.net/old-callback"

	cfg, err := json.Marshal(map[string]any{
		"scopes": []string{"openid"},
		// The dead key, deliberately disagreeing with the column.
		"redirect_uris": []string{stale},
	})
	if err != nil {
		t.Fatal(err)
	}

	store := NewClientStore(&redirSrcApps{app: &resolver.AppConfig{
		ID:             1,
		ClientID:       "client_abc",
		Protocol:       "oidc",
		Status:         1,
		RedirectURIs:   []string{enforced},
		ProtocolConfig: cfg,
	}}, func(string) string { return "/login" })

	client, err := store.ClientByID(context.Background(), "client_abc")
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}

	got := client.RedirectURIs()
	if len(got) != 1 || got[0] != enforced {
		t.Fatalf("RedirectURIs() = %v, want exactly [%s] — the column is the only source of truth", got, enforced)
	}
	for _, u := range got {
		if u == stale {
			t.Fatalf("a protocol_config redirect_uris entry reached the enforced allow-list: %s", u)
		}
	}
}

// An app whose protocol_config has no redirect_uris key at all behaves
// identically — that is the normal shape for anything created through the
// console, and 8 production apps additionally have the key with a stale value.
func TestRedirectURIsIgnoreAbsentProtocolConfigKey(t *testing.T) {
	const enforced = "https://app.example.com/callback"

	store := NewClientStore(&redirSrcApps{app: &resolver.AppConfig{
		ID:             1,
		ClientID:       "client_abc",
		Protocol:       "oidc",
		Status:         1,
		RedirectURIs:   []string{enforced},
		ProtocolConfig: json.RawMessage(`{"scopes":["openid"]}`),
	}}, func(string) string { return "/login" })

	client, err := store.ClientByID(context.Background(), "client_abc")
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}
	if got := client.RedirectURIs(); len(got) != 1 || got[0] != enforced {
		t.Fatalf("RedirectURIs() = %v, want [%s]", got, enforced)
	}
}

// clientConfig is the parsed view of protocol_config. It must have no field for
// redirect URIs: the parsed struct is where a future "just read it from the
// config" change would land, so the absence is asserted rather than assumed.
func TestClientConfigHasNoRedirectURIField(t *testing.T) {
	cfg := parseClientConfig(json.RawMessage(`{"redirect_uris":["https://retired.example.net/x"]}`))
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	for k := range round {
		if k == "redirect_uris" {
			t.Fatalf("clientConfig carries a redirect_uris field (%s); the column is the only source of truth", b)
		}
	}
}

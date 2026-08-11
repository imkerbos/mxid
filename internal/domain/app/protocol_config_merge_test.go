package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

// protocol_config holds settings that no console field renders: claim_mappers,
// jwks, rate_limit_per_min, backchannel_logout_uri. An editor showing a subset
// of the document used to PUT back only what it rendered, and because the write
// replaced the whole blob, everything else was deleted — back-channel logout
// among it, silently, for a live application.
//
// PatchProtocolConfig is the merge that makes a partial write safe. These tests
// pin merge, delete-by-null, and the audit payload that makes a bad overwrite
// reconstructable at all.
//
// Backed by a fake repository rather than the sqlite harness the other tests in
// this package use: the real write goes through gorm.Expr("?::jsonb"), which is
// Postgres-only. What is under test here is the merge, not the SQL dialect.

type fakeConfigRepo struct {
	Repository
	stored []byte
}

func (f *fakeConfigRepo) GetByID(_ context.Context, id int64) (*App, error) {
	return &App{ID: id, Protocol: "oidc", ProtocolConfig: f.stored}, nil
}

func (f *fakeConfigRepo) UpdateProtocolConfig(_ context.Context, _ int64, config []byte) error {
	f.stored = config
	return nil
}

func newProtocolConfigService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	seed := `{"scopes":["openid","groups"],"claim_mappers":[{"claim":"dept","source":"user.detail.department"}],` +
		`"backchannel_logout_uri":"https://app.example.com/blo","id_token_ttl":600}`
	repo := &fakeConfigRepo{stored: []byte(seed)}
	return NewService(repo, nil, event.NewBus(zap.NewNop())), context.Background()
}

func storedConfig(t *testing.T, svc *Service, ctx context.Context) map[string]any {
	t.Helper()
	cfg, err := svc.GetProtocolConfig(ctx, 1)
	if err != nil {
		t.Fatalf("GetProtocolConfig: %v", err)
	}
	return cfg
}

func TestPatchProtocolConfig_KeepsKeysTheCallerDidNotSend(t *testing.T) {
	svc, ctx := newProtocolConfigService(t)

	// Exactly what the console sends when an operator flips one switch.
	if err := svc.PatchProtocolConfig(ctx, 1, map[string]any{"id_token_userinfo_claims": true}); err != nil {
		t.Fatalf("PatchProtocolConfig: %v", err)
	}

	got := storedConfig(t, svc, ctx)
	if got["backchannel_logout_uri"] != "https://app.example.com/blo" {
		t.Fatalf("back-channel logout endpoint was dropped by a patch that never mentioned it; "+
			"single logout would be off for this app with nothing reported. config=%v", got)
	}
	if got["claim_mappers"] == nil {
		t.Fatalf("claim_mappers dropped by an unrelated patch; config=%v", got)
	}
	if got["id_token_userinfo_claims"] != true {
		t.Fatalf("the patched key did not take effect; config=%v", got)
	}
}

func TestPatchProtocolConfig_NullDeletesAKey(t *testing.T) {
	svc, ctx := newProtocolConfigService(t)

	if err := svc.PatchProtocolConfig(ctx, 1, map[string]any{"backchannel_logout_uri": nil}); err != nil {
		t.Fatalf("PatchProtocolConfig: %v", err)
	}

	got := storedConfig(t, svc, ctx)
	if _, present := got["backchannel_logout_uri"]; present {
		t.Fatalf("an explicit null must remove the key, else a setting can never be cleared; config=%v", got)
	}
	if got["claim_mappers"] == nil {
		t.Fatalf("deleting one key must not disturb the others; config=%v", got)
	}
}

// TestUpdateProtocolConfig_StillReplaces pins that PUT keeps its destructive
// meaning. It is the documented difference between the two entry points, and a
// caller that holds the whole document depends on being able to drop keys.
func TestUpdateProtocolConfig_StillReplaces(t *testing.T) {
	svc, ctx := newProtocolConfigService(t)

	if err := svc.UpdateProtocolConfig(ctx, 1, map[string]any{"scopes": []string{"openid"}}); err != nil {
		t.Fatalf("UpdateProtocolConfig: %v", err)
	}

	got := storedConfig(t, svc, ctx)
	if _, present := got["claim_mappers"]; present {
		t.Fatalf("replace semantics must still drop unlisted keys; config=%v", got)
	}
}

// TestPatchProtocolConfig_AuditCarriesBeforeAndAfter is the recovery path. The
// app table keeps no history, so if the audit entry does not carry the previous
// document, a mistaken overwrite cannot be reconstructed from anything short of
// a database backup — which is the situation this whole change came out of.
func TestPatchProtocolConfig_AuditCarriesBeforeAndAfter(t *testing.T) {
	svc, ctx := newProtocolConfigService(t)

	// The bus dispatches handlers on their own goroutines, so wait for the
	// event rather than reading a variable the publisher may not have set yet.
	got := make(chan map[string]any, 1)
	svc.eventBus.Subscribe(event.AppUpdated, func(_ context.Context, e event.Event) {
		p, _ := e.Payload.(map[string]any)
		got <- p
	})

	if err := svc.PatchProtocolConfig(ctx, 1, map[string]any{"id_token_ttl": 900}); err != nil {
		t.Fatalf("PatchProtocolConfig: %v", err)
	}

	var payload map[string]any
	select {
	case payload = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no AppUpdated event published; the change would leave no audit trail")
	}
	if payload == nil {
		t.Fatal("AppUpdated payload was not a map; audit enrichment would drop it")
	}

	before, ok := payload["config_before"].(map[string]any)
	if !ok {
		t.Fatalf("config_before missing or not an object: %#v", payload["config_before"])
	}
	if before["id_token_ttl"] != float64(600) && before["id_token_ttl"] != 600 {
		t.Fatalf("config_before must hold the pre-change value so it can be restored; got %#v", before["id_token_ttl"])
	}
	after, ok := payload["config_after"].(map[string]any)
	if !ok {
		t.Fatalf("config_after missing or not an object: %#v", payload["config_after"])
	}
	if after["id_token_ttl"] != 900 {
		t.Fatalf("config_after must hold the new value; got %#v", after["id_token_ttl"])
	}

	changed, _ := json.Marshal(payload["changed_keys"])
	if string(changed) != `["id_token_ttl"]` {
		t.Fatalf("changed_keys should name exactly what moved, got %s", changed)
	}
}

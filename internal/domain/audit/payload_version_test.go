package audit

// The premise of enriching ChainPayload is that appending fields cannot
// invalidate history, because the entry hash covers the payload BYTES AS
// STORED rather than a re-marshalling of the struct. That premise is load
// bearing — if it were wrong, this change would silently break every existing
// chain — so it is pinned here rather than left as a comment.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// A v1 entry, written before the struct grew any of the v2 fields, must still
// verify byte-for-byte after the struct has grown them.
func TestLegacyPayloadBytesStillVerify(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")

	// Exactly what the old writer produced: no version, no actor_name, no geo.
	legacy := []byte(`{"tenant_id":1,"chain_class":"auth","actor_id":7,"actor_type":"user",` +
		`"event_type":"login.success","resource_type":"","resource_id":0,` +
		`"before":null,"after":null,"ip":"10.0.0.1","user_agent":"ua","session_id":"s",` +
		`"detail":{"event_status":1},"occurred_at":"2026-01-01T00:00:00Z"}`)

	h := ComputeEntryHash(key, 1, GenesisPrevHash, legacy)
	e := &AuditEntry{
		TenantID: 1, ChainClass: "auth", Seq: 1,
		PrevHash: GenesisPrevHash, EntryHash: h, Payload: legacy,
	}
	if err := db.Create(e).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := VerifyChain(context.Background(), db, key, 1, "auth")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("a payload written before enrichment must still verify; got %s at seq %d", res.Reason, res.FailSeq)
	}

	// And it decodes as v1, which is what tells a reader the missing fields were
	// never recorded rather than recorded empty.
	var p ChainPayload
	if err := json.Unmarshal(legacy, &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Version != PayloadV1 {
		t.Fatalf("legacy payload decoded as version %d, want %d", p.Version, PayloadV1)
	}
	if p.ActorName != "" {
		t.Fatalf("legacy payload should carry no actor name, got %q", p.ActorName)
	}
}

// A v1 payload round-trips through the current struct unchanged, so a reader
// that decodes and re-encodes cannot accidentally rewrite history into a
// different canonical form.
func TestV1PayloadRoundTripsUnchanged(t *testing.T) {
	legacy := []byte(`{"tenant_id":1,"chain_class":"auth","actor_id":7,"actor_type":"user",` +
		`"event_type":"login.success","resource_type":"","resource_id":0,` +
		`"before":null,"after":null,"ip":"10.0.0.1","user_agent":"ua","session_id":"s",` +
		`"detail":{"event_status":1},"occurred_at":"2026-01-01T00:00:00Z"}`)

	var p ChainPayload
	if err := json.Unmarshal(legacy, &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out, err := CanonicalJSON(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(out) != string(legacy) {
		t.Fatalf("v1 payload changed shape on round trip.\n got: %s\nwant: %s", out, legacy)
	}
}

// A v2 payload carries the identifiers, and omits the ones that were not
// recorded rather than asserting empty values for them.
func TestV2PayloadCarriesIdentifiersAndOmitsUnknowns(t *testing.T) {
	p := ChainPayload{
		Version: PayloadV2, TenantID: 1, ChainClass: "auth",
		ActorID: 7, ActorType: "user", EventType: "login.success",
		OccurredAt: "2026-01-01T00:00:00Z",
		ActorName:  "Alice", GeoCity: "Shanghai",
	}
	out, err := CanonicalJSON(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["version"] != float64(PayloadV2) {
		t.Fatalf("version = %v, want %d", m["version"], PayloadV2)
	}
	if m["actor_name"] != "Alice" || m["geo_city"] != "Shanghai" {
		t.Fatalf("identifiers missing from payload: %s", out)
	}
	// resource_name and geo_country were not supplied, so they must be absent —
	// not present-and-empty, which would claim the resource had no name.
	if _, ok := m["resource_name"]; ok {
		t.Fatalf("unrecorded resource_name should be omitted, got: %s", out)
	}
	if _, ok := m["geo_country"]; ok {
		t.Fatalf("unrecorded geo_country should be omitted, got: %s", out)
	}
}

// Enriched events must survive the whole pending -> chainer -> entry path with
// their identifiers intact, since that is the path the projection will rebuild
// from.
func TestEnrichedEventReachesTheLedger(t *testing.T) {
	db := newTestDB(t)
	gen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}

	ctx := auditctx.With(context.Background(), auditctx.Actor{
		ActorID: 7, ActorType: "user", ActorName: "Alice", TenantID: 1,
	})
	err = NewCapturer(gen).Capture(ctx, db, Event{
		ChainClass: "data", EventType: "user.updated",
		ResourceType: "user", ResourceID: 42, ResourceName: "alice@example.com",
		GeoCity: "Shanghai", GeoCountry: "CN",
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if _, err := NewChainer(db, []byte("key"), "default", zap.NewNop()).
		ProcessBatch(context.Background(), 10); err != nil {
		t.Fatalf("chain: %v", err)
	}

	var e AuditEntry
	if err := db.Where("chain_class = 'data'").Order("seq desc").First(&e).Error; err != nil {
		t.Fatalf("load entry: %v", err)
	}
	var p ChainPayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if p.Version != PayloadV2 {
		t.Fatalf("version = %d, want %d", p.Version, PayloadV2)
	}
	if p.ResourceName != "alice@example.com" {
		t.Fatalf("resource_name = %q, want alice@example.com", p.ResourceName)
	}
	if p.GeoCity != "Shanghai" || p.GeoCountry != "CN" {
		t.Fatalf("geo lost: city=%q country=%q", p.GeoCity, p.GeoCountry)
	}
	if p.ActorName != "Alice" {
		t.Fatalf("actor_name = %q, want Alice", p.ActorName)
	}
}

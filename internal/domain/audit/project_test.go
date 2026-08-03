package audit

// Rebuilding the projection from the ledger.
//
// The claim being tested is that losing mxid_audit_log costs nothing that the
// ledger cannot restore. So these delete rows and check they come back with
// their content intact, rather than checking that a function returns no error.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ledgerWithEvents drives the real capture -> chainer path so the entries under
// test are shaped exactly like production ones.
func ledgerWithEvents(t *testing.T, db *gorm.DB, events ...Event) {
	t.Helper()
	gen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	ctx := auditctx.With(context.Background(), auditctx.Actor{
		ActorID: 7, ActorType: "user", ActorName: "Alice", TenantID: 1,
		IP: "10.1.2.3", SessionID: "sess-1",
	})
	cap := NewCapturer(gen)
	for i := range events {
		if err := cap.Capture(ctx, db, events[i]); err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
	}
	if _, err := NewChainer(db, []byte("key"), "default", zap.NewNop()).
		ProcessBatch(context.Background(), 100); err != nil {
		t.Fatalf("chain: %v", err)
	}
}

func TestRebuildRestoresRowsWithTheirContent(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ledgerWithEvents(t, db,
		Event{ChainClass: "data", EventType: "group.create",
			ResourceType: "group", ResourceID: 11, ResourceName: "sre",
			GeoCity: "Shanghai", GeoCountry: "CN"},
		Event{ChainClass: "data", EventType: "group_member.create",
			ResourceType: "group_member", ResourceID: 12},
	)

	res, err := RebuildFromLedger(context.Background(), db, 1, "data", 0)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if res.RowsWritten != 2 {
		t.Fatalf("wrote %d rows, want 2 (read %d entries)", res.RowsWritten, res.EntriesRead)
	}

	var rows []AuditLog
	if err := db.Order("created_at asc").Find(&rows).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("projection holds %d rows, want 2", len(rows))
	}

	first := rows[0]
	// The identifiers are the point: an id alone stops identifying anything
	// once the referenced row is renamed or deleted.
	if first.ActorName == nil || *first.ActorName != "Alice" {
		t.Fatalf("actor name not restored: %v", first.ActorName)
	}
	if first.ResourceName == nil || *first.ResourceName != "sre" {
		t.Fatalf("resource name not restored: %v", first.ResourceName)
	}
	if first.GeoCity == nil || *first.GeoCity != "Shanghai" {
		t.Fatalf("geo not restored: %v", first.GeoCity)
	}
	if first.IP == nil || *first.IP != "10.1.2.3" {
		t.Fatalf("ip not restored: %v", first.IP)
	}
	if first.EventType != "group.create" {
		t.Fatalf("event type = %q", first.EventType)
	}
	if first.CreatedAt.IsZero() || time.Since(first.CreatedAt) > time.Hour {
		t.Fatalf("implausible created_at: %v", first.CreatedAt)
	}
	// Reconstructed rows are negative-id by construction, so they can never
	// collide with a natively written snowflake row and are recognisable.
	if first.ID >= 0 {
		t.Fatalf("reconstructed row should carry a negative id, got %d", first.ID)
	}
}

// A rebuild is a repair run against a table that is usually only partly
// missing, so it must not disturb what survived and must be safe to repeat.
func TestRebuildIsIdempotentAndAdditive(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ledgerWithEvents(t, db,
		Event{ChainClass: "data", EventType: "org.create", ResourceType: "org", ResourceID: 1},
	)

	// A natively written row that the ledger knows nothing about — a read event,
	// which is never chained. It must survive every rebuild.
	native := AuditLog{
		ID: 999, TenantID: 1, ActorType: "user", EventType: "org.read",
		EventStatus: EventStatusSuccess, CreatedAt: time.Now().UTC(),
		Detail: json.RawMessage("{}"),
	}
	if err := db.Create(&native).Error; err != nil {
		t.Fatalf("seed native row: %v", err)
	}

	ctx := context.Background()
	if _, err := RebuildFromLedger(ctx, db, 1, "data", 0); err != nil {
		t.Fatalf("rebuild 1: %v", err)
	}
	second, err := RebuildFromLedger(ctx, db, 1, "data", 0)
	if err != nil {
		t.Fatalf("rebuild 2: %v", err)
	}
	if second.RowsWritten != 0 {
		t.Fatalf("second rebuild wrote %d rows, want 0 — replay must be a no-op", second.RowsWritten)
	}

	var total int64
	if err := db.Model(&AuditLog{}).Count(&total).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Fatalf("projection holds %d rows, want 2 (one rebuilt, one native)", total)
	}
	var stillThere AuditLog
	if err := db.Where("id = 999").First(&stillThere).Error; err != nil {
		t.Fatalf("a log-only row must survive a rebuild: %v", err)
	}
}

// The scenario this exists for: retention dropped a partition, and the
// evidence-bearing rows in it are restored from the ledger.
func TestRebuildAfterProjectionLoss(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ledgerWithEvents(t, db,
		Event{ChainClass: "data", EventType: "app.create", ResourceType: "app", ResourceID: 5, ResourceName: "grafana"},
	)
	ctx := context.Background()
	if _, err := RebuildFromLedger(ctx, db, 1, "data", 0); err != nil {
		t.Fatalf("initial: %v", err)
	}

	// Simulate the loss.
	if err := db.Exec(`DELETE FROM mxid_audit_log`).Error; err != nil {
		t.Fatalf("wipe: %v", err)
	}

	res, err := RebuildFromLedger(ctx, db, 1, "data", 0)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if res.RowsWritten != 1 {
		t.Fatalf("restored %d rows, want 1", res.RowsWritten)
	}
	var row AuditLog
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.ResourceName == nil || *row.ResourceName != "grafana" {
		t.Fatalf("restored row lost its resource name: %+v", row.ResourceName)
	}
}

// A v1 payload predates enrichment, so it can only restore what it holds. It
// must still project rather than being skipped, and must not invent values.
func TestRebuildOfLegacyPayloadOmitsUnrecordedFields(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	legacy := []byte(`{"tenant_id":1,"chain_class":"data","actor_id":7,"actor_type":"user",` +
		`"event_type":"app.update","resource_type":"app","resource_id":5,` +
		`"before":null,"after":null,"ip":"","user_agent":"","session_id":"",` +
		`"detail":{"event_status":1},"occurred_at":"2026-01-01T00:00:00Z"}`)
	h := ComputeEntryHash([]byte("key"), 1, GenesisPrevHash, legacy)
	if err := db.Create(&AuditEntry{
		TenantID: 1, ChainClass: "data", Seq: 1,
		PrevHash: GenesisPrevHash, EntryHash: h, Payload: legacy,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := RebuildFromLedger(context.Background(), db, 1, "data", 0); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	var row AuditLog
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.EventType != "app.update" {
		t.Fatalf("event type = %q", row.EventType)
	}
	// Never recorded, so left NULL rather than restored as "".
	if row.ActorName != nil {
		t.Fatalf("a v1 payload has no actor name; got %q", *row.ActorName)
	}
	if row.GeoCity != nil {
		t.Fatalf("a v1 payload has no geo; got %q", *row.GeoCity)
	}
	var detail map[string]any
	if err := json.Unmarshal(row.Detail, &detail); err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detail["event_status"] != float64(1) {
		t.Fatalf("event status lost: %v", detail)
	}
}

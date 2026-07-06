package audit

// Postgres e2e for the anchor-span unique constraint (migration 000054 /
// AuditAnchor uniqueIndex tag). Skipped unless MXID_E2E_DSN points at a
// THROWAWAY database. Proves a duplicate anchor for the same
// (tenant_id, chain_class, from_seq, to_seq) span is rejected by the DB and
// that AnchorChain does not create a duplicate on a repeat pass — the
// last-resort guard against a failover overlap producing duplicate ledger rows.

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestZZ_E2E_Postgres_AnchorUniqueSpan(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("MXID_E2E_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&AuditPending{}, &AuditEntry{}, &ChainHead{}, &AuditAnchor{}); err != nil {
		t.Fatal(err)
	}
	// The audit tables are shared with the other e2e in this package (they run
	// sequentially against the same DSN). Start from a clean slate and clean up
	// after so this test's seeded rows don't pollute the other's global counts.
	// TRUNCATE bypasses the row-level append-only trigger (which only fires on
	// UPDATE/DELETE), so it works even after that trigger is installed.
	truncate := func() {
		db.Exec("TRUNCATE mxid_audit_pending, mxid_audit_entry, mxid_audit_anchor, mxid_audit_chain_head RESTART IDENTITY")
	}
	truncate()
	t.Cleanup(truncate)
	// Confirm the composite unique index exists (from the model tag / migration).
	var idxCount int64
	if err := db.Raw(
		`SELECT count(*) FROM pg_indexes WHERE indexname = 'uq_audit_anchor_span'`,
	).Scan(&idxCount).Error; err != nil {
		t.Fatal(err)
	}
	if idxCount != 1 {
		t.Fatalf("expected uq_audit_anchor_span index to exist, found %d", idxCount)
	}

	const tenant int64 = 99
	const class = "data"
	gen := newTestIDGen(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, tenant, class, "e")
	}
	if _, err := NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(ctx, 100); err != nil {
		t.Fatalf("chain: %v", err)
	}

	anchorer := NewAnchorer(db, testKey(t), NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())

	first, err := anchorer.AnchorChain(ctx, tenant, class)
	if err != nil {
		t.Fatalf("first anchor: %v", err)
	}
	if first == nil {
		t.Fatal("expected first anchor to be created")
	}

	// A raw duplicate insert of the same span must be rejected by the DB.
	dup := *first
	dup.ID = gen.Generate()
	if err := db.WithContext(ctx).Create(&dup).Error; err == nil {
		t.Fatal("expected duplicate anchor span insert to be rejected by uq_audit_anchor_span")
	}

	// A repeat AnchorChain with no new entries returns nil and creates nothing.
	again, err := anchorer.AnchorChain(ctx, tenant, class)
	if err != nil {
		t.Fatalf("second anchor should skip, got: %v", err)
	}
	if again != nil {
		t.Fatal("expected no new anchor on the second pass")
	}

	var rows int64
	db.Model(&AuditAnchor{}).Where("tenant_id = ? AND chain_class = ?", tenant, class).Count(&rows)
	if rows != 1 {
		t.Fatalf("expected exactly 1 anchor row for the span, got %d", rows)
	}
	t.Log("E2E PASS: duplicate anchor span rejected; ledger has exactly one row")
}

package audit

import (
	"bytes"
	"context"
	"testing"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func seedPending(t *testing.T, db *gorm.DB, gen *snowflake.Generator, tenant int64, class, evt string) {
	t.Helper()
	cap := NewCapturer(gen)
	ctx := auditctx.With(context.Background(), auditctx.Actor{TenantID: tenant, ActorID: 1, ActorType: "admin"})
	if err := cap.Capture(ctx, db, Event{ChainClass: class, EventType: evt}); err != nil {
		t.Fatal(err)
	}
}

func TestChainer_ChainsInOrder(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "e1")
	seedPending(t, db, gen, 7, "data", "e2")
	seedPending(t, db, gen, 7, "data", "e3")

	c := NewChainer(db, []byte("key"), "default", zap.NewNop())
	n, err := c.ProcessBatch(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("processed %d, want 3", n)
	}

	var entries []AuditEntry
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").Order("seq asc").Find(&entries)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Seq != 1 || entries[1].Seq != 2 || entries[2].Seq != 3 {
		t.Fatalf("seq not 1,2,3: %d,%d,%d", entries[0].Seq, entries[1].Seq, entries[2].Seq)
	}
	if !bytes.Equal(entries[0].PrevHash, GenesisPrevHash) {
		t.Fatalf("first prev_hash not genesis")
	}
	if !bytes.Equal(entries[1].PrevHash, entries[0].EntryHash) {
		t.Fatalf("chain link broken between seq 1 and 2")
	}
	if !bytes.Equal(entries[2].PrevHash, entries[1].EntryHash) {
		t.Fatalf("chain link broken between seq 2 and 3")
	}

	var nPending int64
	db.Model(&AuditPending{}).Count(&nPending)
	if nPending != 0 {
		t.Fatalf("pending not drained: %d left", nPending)
	}
}

func TestChainer_SeparateChainsPerClass(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "d1")
	seedPending(t, db, gen, 7, "auth", "a1")

	c := NewChainer(db, []byte("key"), "default", zap.NewNop())
	if _, err := c.ProcessBatch(context.Background(), 100); err != nil {
		t.Fatal(err)
	}

	var dataHead, authHead ChainHead
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").First(&dataHead)
	db.Where("tenant_id = ? AND chain_class = ?", 7, "auth").First(&authHead)
	if dataHead.LastSeq != 1 || authHead.LastSeq != 1 {
		t.Fatalf("each class should start at seq 1: data=%d auth=%d", dataHead.LastSeq, authHead.LastSeq)
	}
}

package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

func chainedDB(t *testing.T) (*gorm.DB, []byte) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "e1")
	seedPending(t, db, gen, 7, "data", "e2")
	seedPending(t, db, gen, 7, "data", "e3")
	key := []byte("key")
	c := NewChainer(db, key, "default", zap.NewNop())
	if _, err := c.ProcessBatch(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	return db, key
}

func TestVerify_CleanChainOK(t *testing.T) {
	db, key := chainedDB(t)
	res, err := VerifyChain(context.Background(), db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.VerifiedThrough != 3 {
		t.Fatalf("clean chain failed: %+v", res)
	}
}

func TestVerify_TamperedPayloadDetected(t *testing.T) {
	db, key := chainedDB(t)
	// Tamper: overwrite payload of seq 2 directly (simulating a DB-level edit).
	db.Model(&AuditEntry{}).
		Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).
		Update("payload", []byte(`{"tampered":true}`))

	res, err := VerifyChain(context.Background(), db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.FailSeq != 2 {
		t.Fatalf("tamper not detected at seq 2: %+v", res)
	}
}

func TestVerify_DeletionDetected(t *testing.T) {
	db, key := chainedDB(t)
	// Delete seq 2 -> gap.
	db.Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).Delete(&AuditEntry{})

	res, err := VerifyChain(context.Background(), db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Reason != "seq gap" {
		t.Fatalf("deletion not detected: %+v", res)
	}
}

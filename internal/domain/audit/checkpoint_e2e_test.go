package audit

// Postgres end-to-end tests for pruning. Skipped unless MXID_E2E_DSN points at
// a THROWAWAY database.
//
// These cannot be unit tests. The guarantee being exercised lives in a
// PostgreSQL trigger — that DELETE is refused unless a transaction-local
// setting opens the gate, and that UPDATE is refused regardless — and sqlite
// has no such trigger, so an in-memory test would assert against a world where
// the protection does not exist.

import (
	"context"
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// pruneTenant gives each test its own slice of the shared e2e database.
//
// Truncating instead would be simpler and wrong: the tests in this package
// share one database, so wiping the ledger destroys whatever another test is
// midway through asserting — and the failure surfaces as a confusing result in
// the OTHER test, ordered by nothing more stable than declaration order.
// Seeded per process, not from a fixed base: a fixed base collides with rows
// left behind by an earlier run that crashed before its cleanup, and the
// collision surfaces as a duplicate-key error in whichever test happens to go
// first — a failure that says nothing about the code under test.
var pruneTenantSeq = 90_000_000 + (time.Now().UnixNano()/1000)%1_000_000*100

func pruneTestDB(t *testing.T) (*gorm.DB, int64) {
	t.Helper()
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("set MXID_E2E_DSN to run prune e2e tests (throwaway DB only)")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pruneTenantSeq++
	tenant := pruneTenantSeq
	t.Cleanup(func() {
		// Entries need the gate to be removable, which is itself a small
		// confirmation that the trigger is doing its job.
		db.Transaction(func(tx *gorm.DB) error {
			tx.Exec(`SET LOCAL mxid.audit_prune = 'on'`)
			tx.Exec(`DELETE FROM mxid_audit_entry WHERE tenant_id = ?`, tenant)
			return nil
		})
		db.Exec(`DELETE FROM mxid_audit_anchor WHERE tenant_id = ?`, tenant)
		db.Exec(`DELETE FROM mxid_audit_chain_head WHERE tenant_id = ?`, tenant)
		db.Exec(`DELETE FROM mxid_audit_checkpoint WHERE tenant_id = ?`, tenant)
	})
	return db, tenant
}

func prunerFixture(t *testing.T, db *gorm.DB, tenant int64, n int) (key []byte, reg KeyRegistry, priv ed25519.PrivateKey, hashes [][]byte) {
	t.Helper()
	key = []byte("prune-key")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	reg = KeyRegistry{KeyIDForPublic(pub): pub}

	hashes = seedChain(t, db, key, tenant, "data", n)
	setHead(t, db, tenant, "data", int64(n), hashes[n])

	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if _, err := NewAnchorer(db, priv, nil, idGen, zap.NewNop()).AnchorAll(context.Background()); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	return key, reg, priv, hashes
}

// The append-only guarantee must survive the gate existing at all.
func TestEntriesStillCannotBeDeletedOrUpdatedWithoutTheGate(t *testing.T) {
	db, tenant := pruneTestDB(t)
	key, _, _, _ := prunerFixture(t, db, tenant, 10)
	_ = key

	if err := db.Exec(`DELETE FROM mxid_audit_entry WHERE tenant_id = ? AND seq = 1`, tenant).Error; err == nil {
		t.Fatal("DELETE without the prune gate must still be refused")
	}
	// UPDATE has no legitimate caller and is refused even with the gate open,
	// which is the difference between pruning history and rewriting it.
	err := db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Exec(`SET LOCAL mxid.audit_prune = 'on'`).Error; e != nil {
			return e
		}
		return tx.Exec(`UPDATE mxid_audit_entry SET payload = ? WHERE tenant_id = ? AND seq = 1`, []byte(`{}`), tenant).Error
	})
	if err == nil {
		t.Fatal("UPDATE must be refused even with the prune gate open")
	}
}

func TestPruneLeavesAVerifiableChain(t *testing.T) {
	db, tenant := pruneTestDB(t)
	key, reg, priv, _ := prunerFixture(t, db, tenant, 20)
	ctx := context.Background()

	idGen, err := snowflake.New(2)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	res, err := NewPruner(db, priv, idGen).PruneChain(ctx, tenant, "data", 10)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.PrunedThroughSeq != 10 || res.EntriesDeleted != 10 {
		t.Fatalf("pruned through %d deleting %d, want 10/10", res.PrunedThroughSeq, res.EntriesDeleted)
	}

	// Verifying from genesis must now fail — the prefix really is gone.
	if r, err := VerifyChain(ctx, db, key, tenant, "data"); err != nil {
		t.Fatalf("verify: %v", err)
	} else if r.OK {
		t.Fatal("a pruned chain must not verify from genesis")
	}

	// Verifying from the checkpoint must succeed. This is the whole point: the
	// absence is accounted for, and the account is signed.
	cp, err := LoadCheckpoint(ctx, db, reg, tenant, "data")
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if cp.Seq != 11 {
		t.Fatalf("checkpoint resumes at %d, want 11", cp.Seq)
	}
	r, err := VerifyChainFrom(ctx, db, key, tenant, "data", cp)
	if err != nil {
		t.Fatalf("verify from checkpoint: %v", err)
	}
	if !r.OK || r.VerifiedThrough != 20 {
		t.Fatalf("verify from checkpoint got OK=%v through=%d (%s)", r.OK, r.VerifiedThrough, r.Reason)
	}
}

// Pruning must never outrun the anchors: an unanchored entry has nothing
// attesting that it existed, so removing it would destroy the only record.
func TestPruneStopsAtTheAnchorLine(t *testing.T) {
	db, tenant := pruneTestDB(t)
	key, _, priv, hashes := prunerFixture(t, db, tenant, 10)
	ctx := context.Background()

	// Ten more entries, deliberately left unanchored.
	more := seedChain2(t, db, key, tenant, "data", 11, 20, hashes[10])
	setHead(t, db, tenant, "data", 20, more[len(more)-1])

	idGen, err := snowflake.New(3)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	// Ask to prune everything; only the anchored prefix may go.
	res, err := NewPruner(db, priv, idGen).PruneChain(ctx, tenant, "data", 20)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.PrunedThroughSeq != 10 {
		t.Fatalf("pruned through %d, want 10 — pruning must stop at the anchor line", res.PrunedThroughSeq)
	}
	var remaining int64
	if err := db.Model(&AuditEntry{}).Where("tenant_id = ? AND chain_class = 'data'", tenant).Count(&remaining).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 10 {
		t.Fatalf("%d entries left, want the 10 unanchored ones", remaining)
	}
}

// A forged or corrupted checkpoint must not be silently downgraded to genesis:
// the floor is the thing being trusted, so an untrustworthy floor is an error.
func TestTamperedCheckpointIsRejected(t *testing.T) {
	db, tenant := pruneTestDB(t)
	_, reg, priv, _ := prunerFixture(t, db, tenant, 20)
	ctx := context.Background()

	idGen, err := snowflake.New(4)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if _, err := NewPruner(db, priv, idGen).PruneChain(ctx, tenant, "data", 10); err != nil {
		t.Fatalf("prune: %v", err)
	}

	// Move the floor forward without re-signing, the way an attacker hiding
	// entries 11-15 would.
	if err := db.Exec(`UPDATE mxid_audit_checkpoint SET pruned_through_seq = 15 WHERE tenant_id = ?`, tenant).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := LoadCheckpoint(ctx, db, reg, tenant, "data"); err == nil {
		t.Fatal("a checkpoint whose signature no longer matches must be rejected")
	}
}

// Time-based pruning resolves its boundary through the anchors, so it must
// prune the ranges sealed before the cutoff and leave the ones sealed after it.
func TestPruneChainsBeforeRespectsTheCutoff(t *testing.T) {
	db, tenant := pruneTestDB(t)
	key, reg, priv, hashes := prunerFixture(t, db, tenant, 10)
	ctx := context.Background()

	// Age the first anchor so it falls before the cutoff.
	cutoff := time.Now().Add(-24 * time.Hour)
	if err := db.Exec(`UPDATE mxid_audit_anchor SET created_at = ? WHERE tenant_id = ?`,
		cutoff.Add(-time.Hour), tenant).Error; err != nil {
		t.Fatalf("age anchor: %v", err)
	}

	// A second range, sealed now, therefore after the cutoff.
	more := seedChain2(t, db, key, tenant, "data", 11, 20, hashes[10])
	setHead(t, db, tenant, "data", 20, more[len(more)-1])
	idGen, err := snowflake.New(5)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if _, err := NewAnchorer(db, priv, nil, idGen, zap.NewNop()).AnchorAll(ctx); err != nil {
		t.Fatalf("anchor: %v", err)
	}

	pruneGen, err := snowflake.New(6)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	results, err := NewPruner(db, priv, pruneGen).PruneChainsBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}

	var mine *PruneResult
	for i := range results {
		if results[i].TenantID == tenant {
			mine = &results[i]
		}
	}
	if mine == nil {
		t.Fatal("the aged range should have been pruned")
	}
	if mine.PrunedThroughSeq != 10 {
		t.Fatalf("pruned through %d, want 10 — the range sealed after the cutoff must survive", mine.PrunedThroughSeq)
	}

	// What remains must still verify from the checkpoint.
	cp, err := LoadCheckpoint(ctx, db, reg, tenant, "data")
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	r, err := VerifyChainFrom(ctx, db, key, tenant, "data", cp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.OK || r.VerifiedThrough != 20 {
		t.Fatalf("after a time-based prune the remainder must verify; got OK=%v through=%d (%s)",
			r.OK, r.VerifiedThrough, r.Reason)
	}
}

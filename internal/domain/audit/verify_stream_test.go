package audit

// Tests for streaming verification and checkpoint-relative verification.
//
// The batching is the interesting part: a chain shorter than one batch would
// pass with any implementation, correct or not, so these deliberately cross
// batch boundaries.

import (
	"context"
	"crypto/ed25519"
	"testing"

	"gorm.io/gorm"
)

// seedChain writes n valid, correctly-linked entries and returns the entry hash
// of each seq (1-indexed; index 0 is the genesis prev-hash).
func seedChain(t *testing.T, db *gorm.DB, key []byte, tenantID int64, class string, n int) [][]byte {
	t.Helper()
	hashes := make([][]byte, n+1)
	hashes[0] = GenesisPrevHash
	prev := GenesisPrevHash
	for i := 1; i <= n; i++ {
		payload := []byte(`{"n":` + itoa(i) + `}`)
		h := ComputeEntryHash(key, int64(i), prev, payload)
		e := &AuditEntry{
			TenantID: tenantID, ChainClass: class, Seq: int64(i),
			PrevHash: prev, EntryHash: h, Payload: payload,
		}
		if err := db.Create(e).Error; err != nil {
			t.Fatalf("seed entry %d: %v", i, err)
		}
		prev = h
		hashes[i] = h
	}
	return hashes
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestVerifyChainStreamsAcrossBatchBoundaries(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	// Deliberately more than two batches, and not a multiple of the batch size,
	// so an off-by-one at a boundary shows up.
	const n = verifyBatchSize*2 + 7
	seedChain(t, db, key, 1, "data", n)

	res, err := VerifyChain(context.Background(), db, key, 1, "data")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain should verify clean, got fail at seq %d (%s)", res.FailSeq, res.Reason)
	}
	if res.VerifiedThrough != n {
		t.Fatalf("VerifiedThrough = %d, want %d", res.VerifiedThrough, n)
	}
}

// A gap several batches in must still be found — this is the case where a
// batched implementation can silently restart its expectations per batch.
func TestVerifyChainFindsGapBeyondFirstBatch(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	const n = verifyBatchSize*2 + 50
	seedChain(t, db, key, 1, "data", n)

	victim := int64(verifyBatchSize + 500)
	if err := db.Exec(
		`DELETE FROM mxid_audit_entry WHERE tenant_id = 1 AND chain_class = 'data' AND seq = ?`, victim).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}

	res, err := VerifyChain(context.Background(), db, key, 1, "data")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("deleting an entry must fail verification")
	}
	if res.FailSeq != victim || res.Reason != "seq gap" {
		t.Fatalf("got fail seq %d (%s), want seq %d (seq gap)", res.FailSeq, res.Reason, victim)
	}
}

func TestVerifyChainFromCheckpointSkipsEarlierEntries(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	const n = 500
	hashes := seedChain(t, db, key, 1, "data", n)

	// Simulate an archived-and-pruned prefix: drop everything below 200 and
	// verify from a checkpoint at that boundary. Genesis-anchored verification
	// would report a seq gap here; that is exactly the property that makes
	// retention impossible without checkpoints.
	const cut = 200
	if err := db.Exec(
		`DELETE FROM mxid_audit_entry WHERE tenant_id = 1 AND chain_class = 'data' AND seq < ?`, cut).Error; err != nil {
		t.Fatalf("prune: %v", err)
	}

	if res, err := VerifyChain(context.Background(), db, key, 1, "data"); err != nil {
		t.Fatalf("verify: %v", err)
	} else if res.OK {
		t.Fatal("verifying from genesis over a pruned prefix must fail")
	}

	cp := Checkpoint{Seq: cut, PrevHash: hashes[cut-1]}
	res, err := VerifyChainFrom(context.Background(), db, key, 1, "data", cp)
	if err != nil {
		t.Fatalf("verify from checkpoint: %v", err)
	}
	if !res.OK {
		t.Fatalf("verify from checkpoint failed at seq %d (%s)", res.FailSeq, res.Reason)
	}
	if res.VerifiedThrough != n {
		t.Fatalf("VerifiedThrough = %d, want %d", res.VerifiedThrough, n)
	}
}

// A checkpoint must not become a way to launder a tampered chain: starting
// after the damage is legitimate, but damage AFTER the checkpoint must still
// be caught, and a checkpoint whose hash does not match must be rejected.
func TestCheckpointDoesNotHideTamperingAfterIt(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	const n = 300
	hashes := seedChain(t, db, key, 1, "data", n)

	// Tamper with a payload after the checkpoint. Bound as []byte rather than a
	// SQL literal: payload is a bytes column, and a string literal comes back
	// from sqlite as a type json.RawMessage cannot scan.
	if err := db.Exec(
		`UPDATE mxid_audit_entry SET payload = ? WHERE tenant_id = 1 AND chain_class = 'data' AND seq = 250`,
		[]byte(`{"n":"tampered"}`)).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	cp := Checkpoint{Seq: 200, PrevHash: hashes[199]}
	res, err := VerifyChainFrom(context.Background(), db, key, 1, "data", cp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("tampering after the checkpoint must still be detected")
	}
	if res.FailSeq != 250 || res.Reason != "hash mismatch" {
		t.Fatalf("got seq %d (%s), want 250 (hash mismatch)", res.FailSeq, res.Reason)
	}

	// A checkpoint asserting the wrong prev-hash must be rejected at its very
	// first entry, so a forged checkpoint cannot vouch for a forged chain.
	bad := Checkpoint{Seq: 200, PrevHash: []byte("not the real hash even a little")}
	res, err = VerifyChainFrom(context.Background(), db, key, 1, "data", bad)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK || res.FailSeq != 200 || res.Reason != "prev_hash mismatch" {
		t.Fatalf("forged checkpoint got OK=%v seq=%d (%s), want failure at 200 (prev_hash mismatch)",
			res.OK, res.FailSeq, res.Reason)
	}
}

func TestVerifyAnchorsFromSkipsArchivedRanges(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	const n = 60
	seedChain(t, db, key, 1, "data", n)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	reg := KeyRegistry{KeyIDForPublic(pub): pub}

	// Two anchors: [1,30] and [31,60].
	anchor := func(from, to int64) {
		var leaves [][]byte
		var es []AuditEntry
		if err := db.Where("tenant_id = 1 AND chain_class = 'data' AND seq >= ? AND seq <= ?", from, to).
			Order("seq asc").Find(&es).Error; err != nil {
			t.Fatalf("load: %v", err)
		}
		for i := range es {
			leaves = append(leaves, es[i].EntryHash)
		}
		root := MerkleRoot(leaves)
		a := &AuditAnchor{
			TenantID: 1, ChainClass: "data", FromSeq: from, ToSeq: to,
			MerkleRoot: root, Signature: SignAnchor(priv, 1, "data", from, to, root),
			KeyID: KeyIDForPublic(pub),
		}
		if err := db.Create(a).Error; err != nil {
			t.Fatalf("anchor: %v", err)
		}
	}
	anchor(1, 30)
	anchor(31, 60)

	// Archive the first range: drop its entries and its anchor.
	if err := db.Exec(`DELETE FROM mxid_audit_entry WHERE tenant_id = 1 AND chain_class = 'data' AND seq <= 30`).Error; err != nil {
		t.Fatalf("prune entries: %v", err)
	}
	if err := db.Exec(`DELETE FROM mxid_audit_anchor WHERE tenant_id = 1 AND chain_class = 'data' AND to_seq <= 30`).Error; err != nil {
		t.Fatalf("prune anchor: %v", err)
	}

	if res, err := VerifyAnchors(context.Background(), db, reg, 1, "data"); err != nil {
		t.Fatalf("verify: %v", err)
	} else if res.OK {
		t.Fatal("anchor coverage from seq 1 must fail once the first range is archived")
	}

	res, err := VerifyAnchorsFrom(context.Background(), db, reg, 1, "data", 31)
	if err != nil {
		t.Fatalf("verify from 31: %v", err)
	}
	if !res.OK {
		t.Fatalf("remaining coverage should verify, got fail from %d (%s)", res.FailFromSeq, res.Reason)
	}
	if res.AnchoredThrough != 60 {
		t.Fatalf("AnchoredThrough = %d, want 60", res.AnchoredThrough)
	}
}

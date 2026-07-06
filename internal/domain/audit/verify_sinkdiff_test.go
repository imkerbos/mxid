package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func TestVerifyAnchorsWithSink_DeletedDBRowDetected(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	// clean: sink and DB agree
	res, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("clean sink-diff should pass: %+v err=%v", res, err)
	}
	// delete the DB anchor row (attacker with DB access) — sink copy survives
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").Delete(&AuditAnchor{})
	bad, _ := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if bad.OK || bad.Reason != "sink mismatch" {
		t.Fatalf("deleted DB anchor row not detected via sink: %+v", bad)
	}
}

// TestVerifyAnchorsWithSink_ToleratesRetryOrphan simulates the anchorer's
// non-atomic sink.Put-then-db.Create: a transient DB failure after a
// successful Put leaves an orphan sink record for a from_seq that the next
// tick re-anchors (possibly over a wider range). That orphan must not be
// reported as a "sink mismatch" as long as some DB anchor still starts at the
// same from_seq.
func TestVerifyAnchorsWithSink_ToleratesRetryOrphan(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	// Manually append a retry-orphan: a sink record for the same from_seq (1)
	// but a narrower to_seq (2), as if a prior tick's Put succeeded and the
	// following db.Create failed before the wider (1,3) range above was
	// eventually anchored.
	if _, err := sink.Put(context.Background(), AnchorRecord{
		TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 2,
		MerkleRoot: []byte("orphan-root"), Signature: []byte("orphan-sig"),
		KeyID: "orphan-key",
	}); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("retry-orphan (same from_seq, different to_seq) should be tolerated: %+v err=%v", res, err)
	}
}

// TestVerifyAnchorsWithSink_WiderOrphanDetected covers the attack the
// width-aware sink-diff rule closes: a sink record at a from_seq that is
// WIDER than every DB anchor starting there is not a benign retry-orphan (a
// retry-orphan is by construction narrower than the DB anchor that
// superseded it) — it means the DB anchor that used to cover that width was
// deleted (e.g. an attacker deleted the wide DB anchor and spliced in a
// narrower pre-existing signed sink record). This must be flagged, unlike
// the narrower orphan in TestVerifyAnchorsWithSink_ToleratesRetryOrphan.
func TestVerifyAnchorsWithSink_WiderOrphanDetected(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 5; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	// clean: sink and DB agree, DB max to_seq at from_seq=1 is 5
	res, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("clean sink-diff should pass: %+v err=%v", res, err)
	}

	// Manually append a WIDER sink record at from_seq=1 than any DB anchor
	// covers (DB max to_seq at from_seq=1 is 5; this sink record claims 9).
	// No DB anchor is at least as wide, so this must NOT be tolerated as a
	// retry-orphan.
	if _, err := sink.Put(context.Background(), AnchorRecord{
		TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 9,
		MerkleRoot: []byte("wider-root"), Signature: []byte("wider-sig"),
		KeyID: "wider-key",
	}); err != nil {
		t.Fatal(err)
	}

	bad, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if bad.OK || bad.Reason != "sink mismatch" {
		t.Fatalf("wider sink orphan (uncovered by any DB anchor) not detected: %+v", bad)
	}
}

// TestVerifyAnchorsWithSink_ExtraDBAnchorNotInSink covers the DB -> sink
// direction: a DB anchor row with no sink counterpart at all (never Put, e.g.
// forged directly in the DB) must be caught even though VerifyAnchors alone
// (no sink) would accept it as a valid, contiguous, correctly-signed anchor.
func TestVerifyAnchorsWithSink_ExtraDBAnchorNotInSink(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 5; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	// Anchor seq 1-3 the normal way (sink + DB in sync), then graft a fake
	// DB-only anchor over seq 4-5 below.
	var entries []AuditEntry
	if err := db.Where("tenant_id = ? AND chain_class = ? AND seq <= 3", 7, "data").
		Order("seq asc").Find(&entries).Error; err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 seeded entries seq<=3, got %d", len(entries))
	}
	leaves := make([][]byte, len(entries))
	for i := range entries {
		leaves[i] = entries[i].EntryHash
	}
	root := MerkleRoot(leaves)
	sig := SignAnchor(priv, 7, "data", 1, 3, root)
	if _, err := sink.Put(context.Background(), AnchorRecord{
		TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 3,
		MerkleRoot: root, Signature: sig, KeyID: KeyIDForPublic(priv.Public().(ed25519.PublicKey)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&AuditAnchor{
		ID: gen.Generate(), TenantID: 7, ChainClass: "data",
		FromSeq: 1, ToSeq: 3, MerkleRoot: root, Signature: sig,
		KeyID: KeyIDForPublic(priv.Public().(ed25519.PublicKey)), ExternalURI: "file://seeded",
	}).Error; err != nil {
		t.Fatal(err)
	}

	// Now forge a second DB anchor for seq 4-5 that is internally valid
	// (correct signature and Merkle root over the real entries, contiguous
	// coverage) but was never Put to the sink.
	var tail []AuditEntry
	if err := db.Where("tenant_id = ? AND chain_class = ? AND seq >= 4 AND seq <= 5", 7, "data").
		Order("seq asc").Find(&tail).Error; err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 {
		t.Fatalf("want 2 seeded entries seq 4-5, got %d", len(tail))
	}
	tailLeaves := make([][]byte, len(tail))
	for i := range tail {
		tailLeaves[i] = tail[i].EntryHash
	}
	tailRoot := MerkleRoot(tailLeaves)
	tailSig := SignAnchor(priv, 7, "data", 4, 5, tailRoot)
	if err := db.Create(&AuditAnchor{
		ID: gen.Generate(), TenantID: 7, ChainClass: "data",
		FromSeq: 4, ToSeq: 5, MerkleRoot: tailRoot, Signature: tailSig,
		KeyID: KeyIDForPublic(priv.Public().(ed25519.PublicKey)), ExternalURI: "file://forged",
	}).Error; err != nil {
		t.Fatal(err)
	}

	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))
	res, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Reason != "sink mismatch" {
		t.Fatalf("DB anchor with no sink counterpart not detected: %+v", res)
	}
}

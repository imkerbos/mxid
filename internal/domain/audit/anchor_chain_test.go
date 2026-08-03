package audit

// Tests for the anchor-to-anchor hash chain.
//
// The property that matters: with the external sink off, deleting an anchor row
// used to be invisible to online verification — a coverage hole reads the same
// as a tail that has not been anchored yet. Chaining is what replaces the sink
// as the detector, so these tests are about detection, not about plumbing.

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func anchorTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, KeyRegistry) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv, KeyRegistry{KeyIDForPublic(pub): pub}
}

// newTestAnchorer builds the real anchorer with a nil sink (checkpoint-only
// mode, which is now the default) so the tests exercise the production writer
// rather than hand-built rows.
//
// One instance per test, reused across seals: a fresh snowflake generator on
// the same node id restarts its counter, so building a new one per call hands
// out ids that collide within the same millisecond.
func newTestAnchorer(t *testing.T, db *gorm.DB, priv ed25519.PrivateKey) *Anchorer {
	t.Helper()
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return NewAnchorer(db, priv, nil, idGen, zap.NewNop())
}

func seal(t *testing.T, an *Anchorer) {
	t.Helper()
	if _, err := an.AnchorAll(context.Background()); err != nil {
		t.Fatalf("anchor: %v", err)
	}
}

func setHead(t *testing.T, db *gorm.DB, tenantID int64, class string, lastSeq int64, lastHash []byte) {
	t.Helper()
	h := &ChainHead{TenantID: tenantID, ChainClass: class, LastSeq: lastSeq, LastEntryHash: lastHash}
	if err := db.Save(h).Error; err != nil {
		t.Fatalf("chain head: %v", err)
	}
}

func TestAnchorerChainsAnchorsTogether(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	_, priv, reg := anchorTestKeys(t)
	an := newTestAnchorer(t, db, priv)

	hashes := seedChain(t, db, key, 1, "data", 10)
	setHead(t, db, 1, "data", 10, hashes[10])
	seal(t, an)

	hashes2 := seedChain2(t, db, key, 1, "data", 11, 20, hashes[10])
	setHead(t, db, 1, "data", 20, hashes2[len(hashes2)-1])
	seal(t, an)

	var anchors []AuditAnchor
	if err := db.Where("tenant_id = 1 AND chain_class = 'data'").Order("from_seq asc").Find(&anchors).Error; err != nil {
		t.Fatalf("load anchors: %v", err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2", len(anchors))
	}
	if anchors[0].Version != AnchorV2 || anchors[1].Version != AnchorV2 {
		t.Fatalf("anchors should be written at v2, got %d and %d", anchors[0].Version, anchors[1].Version)
	}
	if len(anchors[0].PrevAnchorHash) != 0 {
		t.Fatal("the first anchor of a chain has no predecessor to commit to")
	}
	want := AnchorHash(&anchors[0])
	if string(anchors[1].PrevAnchorHash) != string(want) {
		t.Fatal("second anchor does not commit to the first")
	}

	res, err := VerifyAnchors(context.Background(), db, reg, 1, "data")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.AnchoredThrough != 20 {
		t.Fatalf("verify got OK=%v through=%d, want true/20 (%s)", res.OK, res.AnchoredThrough, res.Reason)
	}
}

// The whole point: an anchor row removed from the middle must be caught.
func TestDeletingAnAnchorBreaksTheLink(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	_, priv, reg := anchorTestKeys(t)
	an := newTestAnchorer(t, db, priv)

	h1 := seedChain(t, db, key, 1, "data", 10)
	setHead(t, db, 1, "data", 10, h1[10])
	seal(t, an)

	h2 := seedChain2(t, db, key, 1, "data", 11, 20, h1[10])
	setHead(t, db, 1, "data", 20, h2[len(h2)-1])
	seal(t, an)

	h3 := seedChain2(t, db, key, 1, "data", 21, 30, h2[len(h2)-1])
	setHead(t, db, 1, "data", 30, h3[len(h3)-1])
	seal(t, an)

	// Remove the middle anchor. Coverage alone would report a gap; the point is
	// that the link check fires even when an attacker also rewrites from_seq to
	// close that gap, which the next case covers.
	if err := db.Exec(`DELETE FROM mxid_audit_anchor WHERE tenant_id = 1 AND chain_class = 'data' AND from_seq = 11`).Error; err != nil {
		t.Fatalf("delete anchor: %v", err)
	}

	res, err := VerifyAnchors(context.Background(), db, reg, 1, "data")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("deleting an anchor must fail verification")
	}
}

// An attacker who deletes an anchor and repairs the coverage gap by widening a
// neighbour is still caught, because the widened anchor's signature no longer
// matches its contents.
func TestForgingCoverageAfterDeletionIsCaught(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	_, priv, reg := anchorTestKeys(t)
	an := newTestAnchorer(t, db, priv)

	h1 := seedChain(t, db, key, 1, "data", 10)
	setHead(t, db, 1, "data", 10, h1[10])
	seal(t, an)

	h2 := seedChain2(t, db, key, 1, "data", 11, 20, h1[10])
	setHead(t, db, 1, "data", 20, h2[len(h2)-1])
	seal(t, an)

	// Delete the second anchor, then stretch the first to cover its range.
	if err := db.Exec(`DELETE FROM mxid_audit_anchor WHERE tenant_id = 1 AND chain_class = 'data' AND from_seq = 11`).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := db.Exec(`UPDATE mxid_audit_anchor SET to_seq = 20 WHERE tenant_id = 1 AND chain_class = 'data' AND from_seq = 1`).Error; err != nil {
		t.Fatalf("widen: %v", err)
	}

	res, err := VerifyAnchors(context.Background(), db, reg, 1, "data")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("widening an anchor to hide a deletion must fail verification")
	}
	if res.Reason != "bad signature" {
		t.Fatalf("reason = %q, want \"bad signature\"", res.Reason)
	}
}

// Anchors written before this change must keep verifying: the dispatch on
// version is what lets an existing deployment upgrade without invalidating its
// own history.
func TestLegacyV1AnchorsStillVerify(t *testing.T) {
	db := newTestDB(t)
	key := []byte("k")
	pub, priv, reg := anchorTestKeys(t)

	h := seedChain(t, db, key, 1, "data", 10)
	_ = h

	var es []AuditEntry
	if err := db.Where("tenant_id = 1 AND chain_class = 'data'").Order("seq asc").Find(&es).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	leaves := make([][]byte, len(es))
	for i := range es {
		leaves[i] = es[i].EntryHash
	}
	root := MerkleRoot(leaves)

	// Exactly what the old writer produced: v1 preimage, no link, version 1.
	legacy := &AuditAnchor{
		TenantID: 1, ChainClass: "data", FromSeq: 1, ToSeq: 10,
		MerkleRoot: root, Signature: SignAnchor(priv, 1, "data", 1, 10, root),
		KeyID: KeyIDForPublic(pub), Version: AnchorV1,
	}
	if err := db.Create(legacy).Error; err != nil {
		t.Fatalf("create legacy anchor: %v", err)
	}

	res, err := VerifyAnchors(context.Background(), db, reg, 1, "data")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("legacy v1 anchor should still verify, got %s at %d", res.Reason, res.FailFromSeq)
	}
}

// An unrecognised version must fail rather than fall back to the weaker v1
// preimage — otherwise setting version to garbage would be a downgrade attack.
func TestUnknownAnchorVersionIsRejected(t *testing.T) {
	pub, priv, _ := anchorTestKeys(t)
	root := []byte("0123456789abcdef0123456789abcdef")
	a := &AuditAnchor{
		TenantID: 1, ChainClass: "data", FromSeq: 1, ToSeq: 1,
		MerkleRoot: root, Signature: SignAnchor(priv, 1, "data", 1, 1, root),
		KeyID: KeyIDForPublic(pub), Version: 99,
	}
	if VerifyAnchorSig(pub, a) {
		t.Fatal("an unknown anchor version must not verify under an older preimage")
	}
}

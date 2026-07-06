package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

func anchoredDB(t *testing.T) (*gorm.DB, ed25519.PublicKey) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	return db, priv.Public().(ed25519.PublicKey)
}

func TestVerifyAnchors_Clean(t *testing.T) {
	db, pub := anchoredDB(t)
	res, err := VerifyAnchors(context.Background(), db, NewKeyRegistry(pub), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.AnchoredThrough != 3 {
		t.Fatalf("clean anchors failed: %+v", res)
	}
}

func TestVerifyAnchors_TamperedEntryBreaksRoot(t *testing.T) {
	db, pub := anchoredDB(t)
	// tamper an entry's hash inside the anchored range -> recomputed root differs
	db.Model(&AuditEntry{}).Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).
		Update("entry_hash", []byte("tamperedtamperedtamperedtampered"))
	res, _ := VerifyAnchors(context.Background(), db, NewKeyRegistry(pub), 7, "data")
	if res.OK || res.Reason != "root mismatch" {
		t.Fatalf("tamper not caught: %+v", res)
	}
}

func TestVerifyAnchors_WrongKeyFailsSig(t *testing.T) {
	db, pub := anchoredDB(t)
	otherSeed := make([]byte, ed25519.SeedSize)
	otherSeed[0] = 99
	wrongPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	// force a registry entry under the anchor's real key_id that resolves to the
	// wrong public key, so lookup succeeds but the signature check fails
	// (key_id lookup is covered separately by the "unknown key" cases).
	reg := KeyRegistry{KeyIDForPublic(pub): wrongPub}
	res, _ := VerifyAnchors(context.Background(), db, reg, 7, "data")
	if res.OK || res.Reason != "bad signature" {
		t.Fatalf("wrong key not caught: %+v", res)
	}
}

func TestVerifyAnchors_MissingEntryDetected(t *testing.T) {
	db, pub := anchoredDB(t)
	// delete an entry inside the anchored range -> count mismatch
	db.Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).Delete(&AuditEntry{})
	res, _ := VerifyAnchors(context.Background(), db, NewKeyRegistry(pub), 7, "data")
	if res.OK || res.Reason != "missing entries" {
		t.Fatalf("missing entry not caught: %+v", res)
	}
}

func TestVerifyAnchors_RetiredKeyStillVerifies(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 2; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	// anchor with an "old" key
	oldPriv := testKey(t)
	an := NewAnchorer(db, oldPriv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)

	// a NEW current key is now in play, but the registry ALSO holds the retired one
	newSeed := make([]byte, ed25519.SeedSize)
	newSeed[0] = 99
	newPub := ed25519.NewKeyFromSeed(newSeed).Public().(ed25519.PublicKey)
	reg := NewKeyRegistry(newPub, oldPub)

	res, err := VerifyAnchors(context.Background(), db, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("retired-key anchor should verify via registry: %+v err=%v", res, err)
	}
	// registry WITHOUT the old key -> unknown key
	res2, _ := VerifyAnchors(context.Background(), db, NewKeyRegistry(newPub), 7, "data")
	if res2.OK || res2.Reason != "unknown key" {
		t.Fatalf("missing key should be 'unknown key': %+v", res2)
	}
}

func TestVerifyAnchors_DeletedAnchorRowDetected(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil { // [1,3]
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil { // [4,5]
		t.Fatal(err)
	}
	// delete the first anchor -> coverage now starts at seq 4 -> gap
	db.Where("tenant_id = ? AND chain_class = ? AND from_seq = ?", 7, "data", 1).Delete(&AuditAnchor{})
	res, _ := VerifyAnchors(context.Background(), db, NewKeyRegistry(priv.Public().(ed25519.PublicKey)), 7, "data")
	if res.OK || res.Reason != "anchor gap" {
		t.Fatalf("deleted anchor row not detected: %+v", res)
	}
}

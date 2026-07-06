package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func exportFixture(t *testing.T) (*ExportBundle, ed25519.PublicKey) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	an.AnchorChain(context.Background(), 7, "data")
	pub := priv.Public().(ed25519.PublicKey)
	b, err := BuildExport(context.Background(), db, NewKeyRegistry(pub), 7, "data", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	return b, pub
}

func TestVerifyExport_CleanProvesOffline(t *testing.T) {
	b, pub := exportFixture(t)
	res, err := VerifyExport(b, NewKeyRegistry(pub))
	if err != nil || !res.OK || res.AnchoredThrough != 3 {
		t.Fatalf("clean export should prove offline: %+v err=%v", res, err)
	}
}

func TestVerifyExport_TamperedEntryFails(t *testing.T) {
	b, pub := exportFixture(t)
	b.Entries[1].EntryHash = []byte("tamperedtamperedtamperedtampered") // change a hash in the anchored range
	res, _ := VerifyExport(b, NewKeyRegistry(pub))
	if res.OK {
		t.Fatal("tampered entry accepted offline")
	}
}

func TestVerifyExport_UntrustedKeyFails(t *testing.T) {
	b, _ := exportFixture(t)
	other := make([]byte, ed25519.SeedSize)
	other[0] = 77
	wrong := ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)
	res, _ := VerifyExport(b, NewKeyRegistry(wrong))
	if res.OK {
		t.Fatal("export verified against an untrusted key")
	}
}

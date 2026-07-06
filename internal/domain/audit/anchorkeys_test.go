package audit

import (
	"crypto/ed25519"
	"testing"
)

func TestKeyRegistry_ResolvesByKeyID(t *testing.T) {
	seed1 := make([]byte, ed25519.SeedSize)
	seed1[0] = 1
	seed2 := make([]byte, ed25519.SeedSize)
	seed2[0] = 2
	pub1 := ed25519.NewKeyFromSeed(seed1).Public().(ed25519.PublicKey)
	pub2 := ed25519.NewKeyFromSeed(seed2).Public().(ed25519.PublicKey)

	reg := NewKeyRegistry(pub1, pub2)
	got1, ok := reg.For(KeyIDForPublic(pub1))
	if !ok || !got1.Equal(pub1) {
		t.Fatal("pub1 not resolved by its key_id")
	}
	if _, ok := reg.For("deadbeefdeadbeef"); ok {
		t.Fatal("unknown key_id should not resolve")
	}
}

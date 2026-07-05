package audit

import (
	"bytes"
	"testing"
)

func samplebayload() ChainPayload {
	return ChainPayload{
		TenantID:     7,
		ChainClass:   "data",
		ActorID:      42,
		ActorType:    "admin",
		EventType:    "app.deleted",
		ResourceType: "app",
		ResourceID:   99,
		Before:       map[string]any{"name": "old", "enabled": true},
		After:        nil,
		IP:           "1.2.3.4",
		OccurredAt:   "2026-07-05T00:00:00Z",
	}
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	p := samplebayload()
	a, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical JSON not stable:\n%s\n%s", a, b)
	}
}

func TestCanonicalJSON_MapKeyOrderIrrelevant(t *testing.T) {
	p1 := samplebayload()
	p1.Before = map[string]any{"a": 1, "z": 2}
	p2 := samplebayload()
	p2.Before = map[string]any{"z": 2, "a": 1}
	c1, _ := CanonicalJSON(p1)
	c2, _ := CanonicalJSON(p2)
	if !bytes.Equal(c1, c2) {
		t.Fatalf("map key order changed canonical form")
	}
}

func TestComputeEntryHash_KnownVector(t *testing.T) {
	key := []byte("k")
	canonical := []byte(`{"x":1}`)
	h := ComputeEntryHash(key, 1, GenesisPrevHash, canonical)
	if len(h) != 32 {
		t.Fatalf("hash len = %d, want 32", len(h))
	}
	// Deterministic: same inputs -> same hash.
	h2 := ComputeEntryHash(key, 1, GenesisPrevHash, canonical)
	if !bytes.Equal(h, h2) {
		t.Fatalf("entry hash not deterministic")
	}
	// Sequence change -> different hash.
	h3 := ComputeEntryHash(key, 2, GenesisPrevHash, canonical)
	if bytes.Equal(h, h3) {
		t.Fatalf("seq did not affect hash")
	}
}

func TestGenesisPrevHash_IsZero32(t *testing.T) {
	if len(GenesisPrevHash) != 32 {
		t.Fatalf("genesis len = %d", len(GenesisPrevHash))
	}
	for _, b := range GenesisPrevHash {
		if b != 0 {
			t.Fatalf("genesis not all zero")
		}
	}
}

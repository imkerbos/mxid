package audit

import (
	"encoding/binary"
	"encoding/json"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// GenesisPrevHash is the prev_hash of the first real entry (seq=1) in every
// chain: 32 zero bytes.
var GenesisPrevHash = make([]byte, 32)

// ChainPayload is the FROZEN body that gets canonicalized and hashed. Field
// order here is part of the canonical form — do not reorder without a chain
// migration. Map fields (Before/After/Detail) are canonicalized by Go's
// json.Marshal, which sorts map[string]any keys.
type ChainPayload struct {
	TenantID     int64          `json:"tenant_id"`
	ChainClass   string         `json:"chain_class"`
	ActorID      int64          `json:"actor_id"`
	ActorType    string         `json:"actor_type"`
	EventType    string         `json:"event_type"`
	ResourceType string         `json:"resource_type"`
	ResourceID   int64          `json:"resource_id"`
	Before       map[string]any `json:"before"`
	After        map[string]any `json:"after"`
	IP           string         `json:"ip"`
	UserAgent    string         `json:"user_agent"`
	SessionID    string         `json:"session_id"`
	Detail       map[string]any `json:"detail"`
	OccurredAt   string         `json:"occurred_at"` // RFC3339 UTC string, stable across marshals
}

// CanonicalJSON returns the deterministic JSON encoding of p. Struct fields
// serialize in declared order; map keys are sorted by encoding/json.
func CanonicalJSON(p ChainPayload) ([]byte, error) {
	return json.Marshal(p)
}

// ComputeEntryHash returns HMAC-SHA256(key, seq_be8 ‖ prevHash ‖ canonical).
// The byte layout is frozen; verification recomputes it identically.
func ComputeEntryHash(key []byte, seq int64, prevHash []byte, canonical []byte) []byte {
	preimage := make([]byte, 0, 8+len(prevHash)+len(canonical))
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], uint64(seq))
	preimage = append(preimage, seqBuf[:]...)
	preimage = append(preimage, prevHash...)
	preimage = append(preimage, canonical...)
	return crypto.HMACSHA256(key, preimage)
}

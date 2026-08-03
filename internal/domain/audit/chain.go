package audit

import (
	"encoding/binary"
	"encoding/json"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// GenesisPrevHash is the prev_hash of the first real entry (seq=1) in every
// chain: 32 zero bytes.
var GenesisPrevHash = make([]byte, 32)

// Payload format versions. The version travels inside the signed payload, so a
// reader can tell an absent field from a genuinely empty one — the difference
// between "this deployment did not record actor names yet" and "the actor had
// no name".
const (
	// PayloadV1 is the original shape: no version field, no human-readable
	// identifiers. Entries written before enrichment unmarshal to version 0,
	// which is how they are recognised.
	PayloadV1 = 0
	// PayloadV2 adds actor_name, resource_name and geo, so mxid_audit_log can be
	// rebuilt from the ledger rather than being an independent record.
	PayloadV2 = 2
)

// ChainPayload is the body that gets canonicalized and hashed.
//
// Field order is part of the canonical form: do NOT reorder or retype existing
// fields. Appending is safe, and this is worth being precise about because the
// distinction is not obvious — the entry hash is computed over the payload
// BYTES AS STORED (ComputeEntryHash takes []byte, and verification passes
// e.Payload), never over a re-marshalled struct. An older entry therefore
// rehashes to exactly what it did when written, whatever this struct grows
// later. Reordering would break that, because it would change how already-
// stored bytes are interpreted when a payload is decoded.
//
// Map fields (Before/After/Detail) are canonicalized by Go's json.Marshal,
// which sorts map[string]any keys.
type ChainPayload struct {
	// Version is omitted for v1 so existing canonical bytes are unaffected by
	// this struct gaining the field.
	Version      int            `json:"version,omitempty"`
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

	// Human-readable identifiers, added in v2. They are what makes the ledger a
	// complete record: an id alone stops identifying anyone once the referenced
	// row is renamed or deleted, and the audit log that used to hold these is
	// retention-purged. omitempty so an unenriched event does not assert a value
	// it never had.
	ActorName    string `json:"actor_name,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	GeoCity      string `json:"geo_city,omitempty"`
	GeoCountry   string `json:"geo_country,omitempty"`
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

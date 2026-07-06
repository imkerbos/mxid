package audit

import "crypto/ed25519"

// KeyRegistry maps an anchor key_id to the Ed25519 public key that signed it, so
// verification survives key rotation: each anchor carries its key_id, and old
// anchors keep verifying against retired-but-registered public keys.
type KeyRegistry map[string]ed25519.PublicKey

// NewKeyRegistry indexes each public key by its KeyIDForPublic.
func NewKeyRegistry(pubs ...ed25519.PublicKey) KeyRegistry {
	r := make(KeyRegistry, len(pubs))
	for _, p := range pubs {
		if len(p) == 0 {
			continue
		}
		r[KeyIDForPublic(p)] = p
	}
	return r
}

// For returns the public key for a key_id.
func (r KeyRegistry) For(keyID string) (ed25519.PublicKey, bool) {
	p, ok := r[keyID]
	return p, ok
}

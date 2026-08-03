// internal/domain/audit/anchor.go
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/imkerbos/mxid/pkg/crypto"
)

const (
	anchorSigDomain = "mxid-audit-anchor-v1"
	// anchorSigDomainV2 is a DIFFERENT domain string on purpose. Version is also
	// stored in the row, but domain separation means a v1 signature can never be
	// replayed as a v2 one (or the reverse) even if an attacker controls the
	// version column — the preimages cannot collide.
	anchorSigDomainV2 = "mxid-audit-anchor-v2"
)

// Anchor signature preimage versions.
const (
	// AnchorV1 signs (tenant, class, from, to, root). Anchors written before
	// anchors were chained. Still verifiable; never written anymore.
	AnchorV1 int16 = 1
	// AnchorV2 additionally commits to the preceding anchor's hash, which is
	// what makes deleting an anchor detectable.
	AnchorV2 int16 = 2
)

// AnchorSigMessage builds the FROZEN signed message binding a Merkle root to its
// chain and seq range: domain ‖ tenant(be8) ‖ len(class)(be2) ‖ class ‖
// from(be8) ‖ to(be8) ‖ root.
func AnchorSigMessage(tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte {
	buf := make([]byte, 0, len(anchorSigDomain)+8+2+len(class)+8+8+len(root))
	buf = append(buf, anchorSigDomain...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(tenantID))
	buf = append(buf, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], uint16(len(class)))
	buf = append(buf, b2[:]...)
	buf = append(buf, class...)
	binary.BigEndian.PutUint64(b8[:], uint64(fromSeq))
	buf = append(buf, b8[:]...)
	binary.BigEndian.PutUint64(b8[:], uint64(toSeq))
	buf = append(buf, b8[:]...)
	buf = append(buf, root...)
	return buf
}

// KeyIDForPublic is the first 16 hex chars of SHA256(pub) — a short stable id.
func KeyIDForPublic(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// AnchorSigMessageV2 extends the v1 preimage with the preceding anchor's hash,
// so a signature commits to the anchor's position in the sequence and not just
// to the range it covers: domain-v2 ‖ tenant(be8) ‖ len(class)(be2) ‖ class ‖
// from(be8) ‖ to(be8) ‖ len(prev)(be2) ‖ prev ‖ root.
//
// prev is empty for the first anchor of a chain. Its length is encoded so that
// an empty prev cannot be confused with a prev whose bytes happen to prefix the
// root — without the length, the concatenation would be ambiguous.
func AnchorSigMessageV2(tenantID int64, class string, fromSeq, toSeq int64, prevAnchorHash, root []byte) []byte {
	buf := make([]byte, 0, len(anchorSigDomainV2)+8+2+len(class)+8+8+2+len(prevAnchorHash)+len(root))
	buf = append(buf, anchorSigDomainV2...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(tenantID))
	buf = append(buf, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], uint16(len(class)))
	buf = append(buf, b2[:]...)
	buf = append(buf, class...)
	binary.BigEndian.PutUint64(b8[:], uint64(fromSeq))
	buf = append(buf, b8[:]...)
	binary.BigEndian.PutUint64(b8[:], uint64(toSeq))
	buf = append(buf, b8[:]...)
	binary.BigEndian.PutUint16(b2[:], uint16(len(prevAnchorHash)))
	buf = append(buf, b2[:]...)
	buf = append(buf, prevAnchorHash...)
	buf = append(buf, root...)
	return buf
}

// AnchorHash identifies an anchor for the purpose of chaining: SHA-256 over the
// exact preimage its signature covers. Hashing the preimage rather than the
// row means the reference cannot be preserved while the anchor's content is
// altered — any change to what was signed changes the hash its successor
// commits to.
func AnchorHash(a *AuditAnchor) []byte {
	var msg []byte
	if a.Version >= AnchorV2 {
		msg = AnchorSigMessageV2(a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq, a.PrevAnchorHash, a.MerkleRoot)
	} else {
		msg = AnchorSigMessage(a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq, a.MerkleRoot)
	}
	sum := sha256.Sum256(msg)
	return sum[:]
}

// SignAnchor signs the v1 canonical anchor message. Retained for verifying
// history; new anchors are written with SignAnchorV2.
func SignAnchor(priv ed25519.PrivateKey, tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte {
	return crypto.Ed25519Sign(priv, AnchorSigMessage(tenantID, class, fromSeq, toSeq, root))
}

// SignAnchorV2 signs an anchor together with its predecessor's hash.
func SignAnchorV2(priv ed25519.PrivateKey, tenantID int64, class string, fromSeq, toSeq int64, prevAnchorHash, root []byte) []byte {
	return crypto.Ed25519Sign(priv, AnchorSigMessageV2(tenantID, class, fromSeq, toSeq, prevAnchorHash, root))
}

// VerifyAnchorSig recomputes the canonical message from the anchor's fields and
// verifies its signature, choosing the preimage by the anchor's version so rows
// written before chaining keep verifying under the format they were signed
// with. An unknown version is a failure rather than a fallback: silently
// verifying an unrecognised anchor under an older, weaker preimage is exactly
// the downgrade this dispatch exists to prevent.
func VerifyAnchorSig(pub ed25519.PublicKey, a *AuditAnchor) bool {
	var msg []byte
	switch a.Version {
	case AnchorV2:
		msg = AnchorSigMessageV2(a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq, a.PrevAnchorHash, a.MerkleRoot)
	case AnchorV1, 0: // 0 = rows predating the version column
		msg = AnchorSigMessage(a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq, a.MerkleRoot)
	default:
		return false
	}
	return crypto.Ed25519Verify(pub, msg, a.Signature)
}

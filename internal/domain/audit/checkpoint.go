package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// checkpointSigDomain separates checkpoint signatures from anchor signatures.
// Both are made with the same Ed25519 key, so without distinct domains a
// signature over one could be presented as a signature over the other.
const checkpointSigDomain = "mxid-audit-checkpoint-v1"

// pruneGUC is the transaction-local setting the append-only trigger checks
// before allowing a DELETE. See migration 000064 for why the gate exists and
// what it does not protect against.
const pruneGUC = "mxid.audit_prune"

// AuditCheckpoint is the signed floor of a chain: everything at or below
// PrunedThroughSeq has been removed, and PrevHash is the entry hash of that
// last pruned entry — the value the next surviving entry's prev_hash must
// match.
//
// It is what lets an append-only ledger have a retention policy at all.
// Verification resumes from here instead of from genesis, so a missing prefix
// is an accounted-for absence rather than evidence of tampering.
type AuditCheckpoint struct {
	ID               int64     `gorm:"column:id;primaryKey"`
	TenantID         int64     `gorm:"column:tenant_id;not null"`
	ChainClass       string    `gorm:"column:chain_class;not null;size:16"`
	PrunedThroughSeq int64     `gorm:"column:pruned_through_seq;not null"`
	PrevHash         []byte    `gorm:"column:prev_hash;not null"`
	Signature        []byte    `gorm:"column:signature;not null"`
	KeyID            string    `gorm:"column:key_id;not null;size:64"`
	CreatedAt        time.Time `gorm:"column:created_at;not null"`
}

func (AuditCheckpoint) TableName() string { return "mxid_audit_checkpoint" }

// CheckpointSigMessage builds the signed preimage:
// domain ‖ tenant(be8) ‖ len(class)(be2) ‖ class ‖ seq(be8) ‖ prevHash.
func CheckpointSigMessage(tenantID int64, class string, seq int64, prevHash []byte) []byte {
	buf := make([]byte, 0, len(checkpointSigDomain)+8+2+len(class)+8+len(prevHash))
	buf = append(buf, checkpointSigDomain...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(tenantID))
	buf = append(buf, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], uint16(len(class)))
	buf = append(buf, b2[:]...)
	buf = append(buf, class...)
	binary.BigEndian.PutUint64(b8[:], uint64(seq))
	buf = append(buf, b8[:]...)
	buf = append(buf, prevHash...)
	return buf
}

// VerifyCheckpointSig reports whether cp carries a valid signature under pub.
func VerifyCheckpointSig(pub ed25519.PublicKey, cp *AuditCheckpoint) bool {
	msg := CheckpointSigMessage(cp.TenantID, cp.ChainClass, cp.PrunedThroughSeq, cp.PrevHash)
	return crypto.Ed25519Verify(pub, msg, cp.Signature)
}

// LoadCheckpoint returns the verified starting point for a chain: the signed
// checkpoint if one exists, otherwise genesis.
//
// An unverifiable checkpoint is an error rather than a fall back to genesis.
// Falling back would turn a forged or corrupted checkpoint into a confusing
// "seq gap" report, when the real finding is that the floor itself cannot be
// trusted.
func LoadCheckpoint(ctx context.Context, db *gorm.DB, keys KeyRegistry, tenantID int64, class string) (Checkpoint, error) {
	var cp AuditCheckpoint
	err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		First(&cp).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return GenesisCheckpoint(), nil
	case err != nil:
		return Checkpoint{}, fmt.Errorf("load checkpoint: %w", err)
	}
	pub, ok := keys.For(cp.KeyID)
	if !ok {
		return Checkpoint{}, fmt.Errorf("checkpoint for tenant=%d class=%s signed by unknown key %s",
			cp.TenantID, cp.ChainClass, cp.KeyID)
	}
	if !VerifyCheckpointSig(pub, &cp) {
		return Checkpoint{}, fmt.Errorf("checkpoint for tenant=%d class=%s has an invalid signature",
			cp.TenantID, cp.ChainClass)
	}
	return Checkpoint{Seq: cp.PrunedThroughSeq + 1, PrevHash: cp.PrevHash}, nil
}

// Pruner removes chain history that is already sealed under an anchor, leaving
// a signed checkpoint in its place.
type Pruner struct {
	db    *gorm.DB
	priv  ed25519.PrivateKey
	keyID string
	idGen *snowflake.Generator
}

func NewPruner(db *gorm.DB, priv ed25519.PrivateKey, idGen *snowflake.Generator) *Pruner {
	pub := priv.Public().(ed25519.PublicKey)
	return &Pruner{db: db, priv: priv, keyID: KeyIDForPublic(pub), idGen: idGen}
}

// PruneResult reports what one prune removed.
type PruneResult struct {
	TenantID         int64
	ChainClass       string
	PrunedThroughSeq int64
	EntriesDeleted   int64
}

// PruneChain removes entries up to the highest anchored seq that is also at or
// below cutoffSeq, and records a signed checkpoint at that boundary.
//
// Two conditions bound what may go, and both matter:
//
//   - Only ANCHORED entries. An anchor is the durable attestation that the
//     range existed and what it hashed to; pruning past the anchor line would
//     destroy entries nothing has ever committed to.
//   - Only up to cutoffSeq, so the caller decides the retention policy — this
//     function does not invent one.
//
// The whole operation is one transaction: the checkpoint is written before the
// entries are deleted, so a crash midway leaves a chain whose floor is claimed
// but whose entries are still present, which verifies clean. The reverse order
// would leave entries deleted with no floor to explain them — an unverifiable
// chain.
func (p *Pruner) PruneChain(ctx context.Context, tenantID int64, class string, cutoffSeq int64) (PruneResult, error) {
	res := PruneResult{TenantID: tenantID, ChainClass: class}

	// The anchored ceiling. Never prune beyond it.
	var lastAnchor AuditAnchor
	err := p.db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("to_seq desc").First(&lastAnchor).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return res, nil // nothing anchored yet, nothing may be pruned
	case err != nil:
		return res, fmt.Errorf("load last anchor: %w", err)
	}

	through := lastAnchor.ToSeq
	if cutoffSeq < through {
		through = cutoffSeq
	}
	if through < 1 {
		return res, nil
	}

	// The entry at the boundary supplies the hash the checkpoint attests to. If
	// it is already gone, a previous prune covered this range.
	var boundary AuditEntry
	err = p.db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND seq = ?", tenantID, class, through).
		First(&boundary).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return res, nil
	case err != nil:
		return res, fmt.Errorf("load boundary entry: %w", err)
	}

	cp := &AuditCheckpoint{
		ID: p.idGen.Generate(), TenantID: tenantID, ChainClass: class,
		PrunedThroughSeq: through, PrevHash: boundary.EntryHash,
		Signature: crypto.Ed25519Sign(p.priv,
			CheckpointSigMessage(tenantID, class, through, boundary.EntryHash)),
		KeyID: p.keyID, CreatedAt: time.Now().UTC(),
	}

	err = p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Upsert: pruning moves the floor forward, it does not accumulate floors.
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "chain_class"}},
			DoUpdates: clause.AssignmentColumns([]string{"pruned_through_seq", "prev_hash", "signature", "key_id", "created_at"}),
		}).Create(cp).Error; err != nil {
			return fmt.Errorf("write checkpoint: %w", err)
		}
		// Open the append-only gate for THIS transaction only. SET LOCAL is
		// what keeps it from leaking to any later statement on this connection.
		if err := tx.Exec(fmt.Sprintf("SET LOCAL %s = 'on'", pruneGUC)).Error; err != nil {
			return fmt.Errorf("enable prune gate: %w", err)
		}
		out := tx.Exec(
			`DELETE FROM mxid_audit_entry WHERE tenant_id = ? AND chain_class = ? AND seq <= ?`,
			tenantID, class, through)
		if out.Error != nil {
			return fmt.Errorf("delete entries: %w", out.Error)
		}
		res.EntriesDeleted = out.RowsAffected
		return nil
	})
	if err != nil {
		return PruneResult{TenantID: tenantID, ChainClass: class}, err
	}
	res.PrunedThroughSeq = through
	return res, nil
}

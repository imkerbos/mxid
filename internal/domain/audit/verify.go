package audit

import (
	"bytes"
	"context"

	"gorm.io/gorm"
)

// VerifyResult reports the outcome of walking one chain.
type VerifyResult struct {
	OK              bool
	VerifiedThrough int64  // highest seq verified clean
	FailSeq         int64  // seq where verification failed (0 if OK)
	Reason          string // "", "hash mismatch", "seq gap", "prev_hash mismatch"
}

// VerifyChain recomputes the HMAC chain for (tenantID, chainClass) from genesis
// and reports the first inconsistency. A gap in seq means a row was deleted.
func VerifyChain(ctx context.Context, db *gorm.DB, key []byte, tenantID int64, chainClass string) (VerifyResult, error) {
	var entries []AuditEntry
	err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, chainClass).
		Order("seq asc").
		Find(&entries).Error
	if err != nil {
		return VerifyResult{}, err
	}

	prev := GenesisPrevHash
	var expectedSeq int64 = 1
	for _, e := range entries {
		if e.Seq != expectedSeq {
			return VerifyResult{OK: false, VerifiedThrough: expectedSeq - 1, FailSeq: expectedSeq, Reason: "seq gap"}, nil
		}
		if !bytes.Equal(e.PrevHash, prev) {
			return VerifyResult{OK: false, VerifiedThrough: e.Seq - 1, FailSeq: e.Seq, Reason: "prev_hash mismatch"}, nil
		}
		want := ComputeEntryHash(key, e.Seq, prev, e.Payload)
		if !bytes.Equal(want, e.EntryHash) {
			return VerifyResult{OK: false, VerifiedThrough: e.Seq - 1, FailSeq: e.Seq, Reason: "hash mismatch"}, nil
		}
		prev = e.EntryHash
		expectedSeq++
	}
	return VerifyResult{OK: true, VerifiedThrough: expectedSeq - 1}, nil
}

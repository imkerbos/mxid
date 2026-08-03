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

// Checkpoint is a point the chain can be verified FROM, instead of from
// genesis. Seq is the sequence number expected next; PrevHash is the entry hash
// immediately before it.
//
// Genesis is just the checkpoint {Seq: 1, PrevHash: GenesisPrevHash}, so
// verifying a whole chain and verifying a range are the same operation.
//
// This matters beyond convenience: while verification can only ever start at
// seq 1, no entry can ever be removed — a missing row is indistinguishable from
// a deleted one, so retention on the ledger is impossible by construction. A
// checkpoint is what will eventually let an archived range be dropped from the
// hot table while the remainder stays provably intact.
type Checkpoint struct {
	Seq      int64
	PrevHash []byte
}

// GenesisCheckpoint is where a chain starts.
func GenesisCheckpoint() Checkpoint { return Checkpoint{Seq: 1, PrevHash: GenesisPrevHash} }

// verifyBatchSize bounds how many entries are held in memory at once. Entry
// payloads are business-row snapshots and routinely run to kilobytes, so the
// figure is deliberately modest: the cost of a smaller batch is more round
// trips, while the cost of a larger one is paid by the operator whose
// verification run is killed by the OOM reaper.
const verifyBatchSize = 1000

// VerifyChain recomputes the HMAC chain for (tenantID, chainClass) from genesis
// and reports the first inconsistency. A gap in seq means a row was deleted.
func VerifyChain(ctx context.Context, db *gorm.DB, key []byte, tenantID int64, chainClass string) (VerifyResult, error) {
	return VerifyChainFrom(ctx, db, key, tenantID, chainClass, GenesisCheckpoint())
}

// VerifyChainFrom verifies the chain starting at cp, streaming the entries in
// bounded batches rather than materialising the chain in memory.
//
// The previous implementation loaded every entry for the chain into one slice.
// Entries are append-only and never pruned, so that made peak memory a function
// of total history: an audit database large enough to be worth verifying was
// one the verifier could no longer read. Verification has to outlive the data,
// not the other way round.
func VerifyChainFrom(ctx context.Context, db *gorm.DB, key []byte, tenantID int64, chainClass string, cp Checkpoint) (VerifyResult, error) {
	prev := cp.PrevHash
	expectedSeq := cp.Seq
	if expectedSeq < 1 {
		expectedSeq = 1
	}
	cursor := expectedSeq - 1 // highest seq already consumed

	for {
		var batch []AuditEntry
		err := db.WithContext(ctx).
			Where("tenant_id = ? AND chain_class = ? AND seq > ?", tenantID, chainClass, cursor).
			Order("seq asc").
			Limit(verifyBatchSize).
			Find(&batch).Error
		if err != nil {
			return VerifyResult{}, err
		}
		if len(batch) == 0 {
			return VerifyResult{OK: true, VerifiedThrough: expectedSeq - 1}, nil
		}

		for i := range batch {
			e := &batch[i]
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
		cursor = batch[len(batch)-1].Seq
	}
}

// AnchorVerifyResult reports the outcome of checking a chain's anchors.
type AnchorVerifyResult struct {
	OK              bool
	AnchoredThrough int64
	FailFromSeq     int64
	Reason          string // "", "root mismatch", "bad signature", "missing entries", "anchor gap", "unknown key"
}

// VerifyAnchors recomputes each anchor's Merkle root from the stored entries and
// checks its Ed25519 signature. Detects tampering even by a holder of the HMAC
// chain key, provided they do not also hold the anchor private key.
//
// Anchors are always created as a contiguous cover of the chain starting at
// seq 1 ([1,3],[4,4],...), so this also enforces that coverage: a hole in the
// from_seq/to_seq sequence means an anchor row was deleted from
// mxid_audit_anchor. This is a cheap partial hardening, not full tamper
// detection for anchor deletion: if ALL anchors for a chain are deleted, or
// the tail of the chain is simply not yet anchored, this online check cannot
// tell the two apart — that requires diffing against the external sink
// (Phase 4 export).
func VerifyAnchors(ctx context.Context, db *gorm.DB, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error) {
	return VerifyAnchorsFrom(ctx, db, keys, tenantID, class, 1)
}

// VerifyAnchorsFrom checks anchor coverage starting at fromSeq rather than at
// seq 1, so a chain whose earlier ranges have been archived away can still have
// the remainder proven contiguous.
func VerifyAnchorsFrom(ctx context.Context, db *gorm.DB, keys KeyRegistry, tenantID int64, class string, fromSeq int64) (AnchorVerifyResult, error) {
	if fromSeq < 1 {
		fromSeq = 1
	}
	var anchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND to_seq >= ?", tenantID, class, fromSeq).
		Order("from_seq asc").Find(&anchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	through := fromSeq - 1
	expectedFrom := fromSeq
	for i := range anchors {
		a := &anchors[i]
		if a.FromSeq != expectedFrom {
			return AnchorVerifyResult{OK: false, AnchoredThrough: expectedFrom - 1, FailFromSeq: a.FromSeq, Reason: "anchor gap"}, nil
		}
		pub, ok := keys.For(a.KeyID)
		if !ok {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
		if !VerifyAnchorSig(pub, a) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "bad signature"}, nil
		}
		// Stream the range's hashes. An anchor normally covers one 60s tick, but
		// a burst — a bulk import, or a backlog drained after the anchorer was
		// down — can make a single range arbitrarily large, so the range is read
		// in batches too. Only the 32-byte hashes are retained; the payloads,
		// which are the bulk of an entry, are dropped as each batch is consumed.
		leaves := make([][]byte, 0, a.ToSeq-a.FromSeq+1)
		cursor := a.FromSeq - 1
		for cursor < a.ToSeq {
			var batch []AuditEntry
			if err := db.WithContext(ctx).
				Select("seq", "entry_hash").
				Where("tenant_id = ? AND chain_class = ? AND seq > ? AND seq <= ?", tenantID, class, cursor, a.ToSeq).
				Order("seq asc").Limit(verifyBatchSize).Find(&batch).Error; err != nil {
				return AnchorVerifyResult{}, err
			}
			if len(batch) == 0 {
				break
			}
			for j := range batch {
				leaves = append(leaves, batch[j].EntryHash)
			}
			cursor = batch[len(batch)-1].Seq
		}
		if int64(len(leaves)) != a.ToSeq-a.FromSeq+1 {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "missing entries"}, nil
		}
		if !bytes.Equal(MerkleRoot(leaves), a.MerkleRoot) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "root mismatch"}, nil
		}
		expectedFrom = a.ToSeq + 1
		through = a.ToSeq
	}
	return AnchorVerifyResult{OK: true, AnchoredThrough: through}, nil
}

// VerifyAnchorsWithSink runs the DB-side anchor verification, then cross-checks
// the external sink so that DELETING a DB anchor row (which VerifyAnchors alone
// reports only as a coverage gap, and not at all if the whole tail is dropped)
// is caught: the signed copy in the sink survives a DB compromise.
//
// The two directions are reconciled differently:
//   - DB -> sink: every DB anchor MUST have an exact sink match on
//     (from_seq, to_seq, root, sig). Any miss or mismatch means the DB row was
//     tampered with or forged after the fact — flagged unconditionally.
//   - sink -> DB: a sink record with no identical (from_seq, to_seq) DB row is
//     flagged as a deletion UNLESS some DB anchor at that from_seq is at least
//     as WIDE (to_seq >= the sink record's to_seq). This tolerates the
//     anchorer's benign retry-orphans: Anchorer.AnchorChain does sink.Put then
//     db.Create, not atomically, so a transient DB failure after a successful
//     Put leaves an orphan sink record whose from_seq is later re-anchored
//     over an equal-or-wider range by the next tick. A retry-orphan is by
//     construction narrower than (or equal to) the DB anchor that superseded
//     it, so width-aware coverage is required: tolerating ANY DB anchor at the
//     same from_seq (regardless of width) would let an attacker delete a wide
//     DB anchor, splice in a narrower pre-existing signed sink record as its
//     replacement, and silently drop the uncovered tail of the range from
//     AnchoredThrough coverage.
func VerifyAnchorsWithSink(ctx context.Context, db *gorm.DB, sink AnchorSink, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error) {
	res, err := VerifyAnchors(ctx, db, keys, tenantID, class)
	if err != nil || !res.OK {
		return res, err
	}
	// A nil sink means anchoring runs in checkpoint-only mode: there is no
	// external record, so there is nothing to diff against. The anchors have
	// still been verified above (Merkle root + signature over the entries),
	// which catches a forged or truncated range; the cross-check that a nil
	// sink skips is specifically the one aimed at an attacker who can rewrite
	// the database itself. Guarded here rather than at the call site so a
	// future caller cannot reintroduce a nil dereference.
	if sink == nil {
		return res, nil
	}

	var dbAnchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("from_seq asc").Find(&dbAnchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	sinkAll, err := sink.List(ctx)
	if err != nil {
		return AnchorVerifyResult{}, err
	}
	// index the sink by (tenant,class,from,to)
	type k struct {
		t    int64
		c    string
		f, o int64
	}
	sinkIdx := make(map[k]AnchorRecord)
	for _, r := range sinkAll {
		if r.TenantID == tenantID && r.ChainClass == class {
			sinkIdx[k{r.TenantID, r.ChainClass, r.FromSeq, r.ToSeq}] = r
		}
	}
	dbIdx := make(map[k]bool)
	maxDBToSeqAt := make(map[int64]int64, len(dbAnchors))
	for i := range dbAnchors {
		a := &dbAnchors[i]
		dbIdx[k{a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq}] = true
		if a.ToSeq > maxDBToSeqAt[a.FromSeq] {
			maxDBToSeqAt[a.FromSeq] = a.ToSeq
		}
		sr, ok := sinkIdx[k{a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq}]
		if !ok || !bytes.Equal(sr.MerkleRoot, a.MerkleRoot) || !bytes.Equal(sr.Signature, a.Signature) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: res.AnchoredThrough, FailFromSeq: a.FromSeq, Reason: "sink mismatch"}, nil
		}
	}
	for key, r := range sinkIdx {
		if dbIdx[key] {
			continue // exact match already validated in the DB->sink loop
		}
		// a sink record with no exact DB match is a benign retry-orphan ONLY if a
		// DB anchor at the same from_seq covers at least as wide a range; a wider
		// orphan (or one with no covering DB anchor) means a DB row was deleted.
		if maxTo, ok := maxDBToSeqAt[r.FromSeq]; !ok || maxTo < r.ToSeq {
			return AnchorVerifyResult{OK: false, AnchoredThrough: res.AnchoredThrough, FailFromSeq: r.FromSeq, Reason: "sink mismatch"}, nil
		}
	}
	return res, nil
}

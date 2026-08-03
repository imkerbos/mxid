// internal/domain/audit/anchorer.go
package audit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/metrics"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Anchorer summarizes the un-anchored tail of each chain into a signed Merkle
// root. Single-writer per process (run one).
//
// An anchor serves two distinct purposes, and they are worth separating because
// only one of them is universally wanted:
//
//   - Checkpoint (always). The (from_seq, to_seq, merkle_root) row in
//     mxid_audit_anchor summarises a range of the chain in ~375 bytes. That is
//     what makes it possible to verify — and eventually to archive and prune —
//     a range without walking the chain from genesis.
//
//   - External witness (optional, sink != nil). Writing the signed root
//     somewhere outside the database is what would catch an attacker who holds
//     database write access and rewrites history, since they cannot also
//     rewrite the external copy. That guarantee is only real if the sink is
//     genuinely outside the DB's trust domain; a file on a pod's own volume is
//     not, which is why it is opt-in rather than the default.
//
// With sink == nil the chain still detects tampering by anyone who lacks the
// HMAC chain key, and the append-only trigger still blocks deletion. What is
// given up is the ability to prove that an operator with full database access
// did not rewrite history.
type Anchorer struct {
	db     *gorm.DB
	priv   ed25519.PrivateKey
	keyID  string
	sink   AnchorSink
	idGen  *snowflake.Generator
	logger *zap.Logger
}

// NewAnchorer builds an anchorer. sink may be nil, in which case anchors are
// recorded in the database as checkpoints only — see the type comment for what
// that trades away.
func NewAnchorer(db *gorm.DB, priv ed25519.PrivateKey, sink AnchorSink, idGen *snowflake.Generator, logger *zap.Logger) *Anchorer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Anchorer{db: db, priv: priv, keyID: KeyIDForPublic(pub), sink: sink, idGen: idGen, logger: logger}
}

// AnchorChain anchors entries with seq greater than the chain's last anchored
// to_seq. Returns nil if there is nothing new.
func (a *Anchorer) AnchorChain(ctx context.Context, tenantID int64, class string) (*AuditAnchor, error) {
	var lastTo int64
	row := a.db.WithContext(ctx).Model(&AuditAnchor{}).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Select("COALESCE(MAX(to_seq), 0)")
	if err := row.Scan(&lastTo).Error; err != nil {
		return nil, err
	}

	var entries []AuditEntry
	if err := a.db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND seq > ?", tenantID, class, lastTo).
		Order("seq asc").Find(&entries).Error; err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	leaves := make([][]byte, len(entries))
	for i := range entries {
		leaves[i] = entries[i].EntryHash
	}
	root := MerkleRoot(leaves)
	fromSeq := entries[0].Seq
	toSeq := entries[len(entries)-1].Seq

	// Commit to the preceding anchor so the anchors form a chain of their own.
	// Without this an anchor row could be deleted outright and online
	// verification could not tell: a hole in coverage reads the same as a tail
	// that simply has not been anchored yet.
	var prevHash []byte
	var prevAnchor AuditAnchor
	err := a.db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("to_seq desc").First(&prevAnchor).Error
	switch {
	case err == nil:
		prevHash = AnchorHash(&prevAnchor)
	case errors.Is(err, gorm.ErrRecordNotFound):
		// First anchor of this chain: nothing to commit to.
	default:
		return nil, fmt.Errorf("load preceding anchor: %w", err)
	}

	sig := SignAnchorV2(a.priv, tenantID, class, fromSeq, toSeq, prevHash, root)

	var uri string
	if a.sink != nil {
		// Sink first, and a failure aborts the whole anchor: the external record
		// is the point of running a sink at all, so an anchor that exists only in
		// the database would be a witness that cannot witness. Retried next tick.
		var err error
		uri, err = a.sink.Put(ctx, AnchorRecord{
			TenantID: tenantID, ChainClass: class, FromSeq: fromSeq, ToSeq: toSeq,
			MerkleRoot: root, Signature: sig, KeyID: a.keyID, CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return nil, err
		}
	}

	anchor := &AuditAnchor{
		ID: a.idGen.Generate(), TenantID: tenantID, ChainClass: class,
		FromSeq: fromSeq, ToSeq: toSeq, MerkleRoot: root, Signature: sig,
		KeyID: a.keyID, Version: AnchorV2, PrevAnchorHash: prevHash,
		ExternalURI: uri, CreatedAt: time.Now().UTC(),
	}
	if err := a.db.WithContext(ctx).Create(anchor).Error; err != nil {
		// Last-resort guard: another anchorer (a failover overlap) already
		// recorded this exact span. Treat as done rather than erroring so the
		// tick doesn't spin. The leader lock makes this path rare.
		if dberr.IsUniqueViolationOn(err, "uq_audit_anchor_span", "mxid_audit_anchor.tenant_id") {
			a.logger.Info("audit anchorer: span already anchored, skipping",
				zap.Int64("tenant_id", tenantID), zap.String("chain_class", class),
				zap.Int64("from_seq", fromSeq), zap.Int64("to_seq", toSeq))
			return nil, nil
		}
		return nil, err
	}
	return anchor, nil
}

// reportLag publishes, per chain, how many entries are written but not yet
// sealed into an anchor. Entries only become verifiable as a range once
// anchored, so a lag that keeps growing is a growing window of history that
// cannot be proven intact — and, like a stalled chainer, nothing else surfaces
// it.
func (a *Anchorer) reportLag(ctx context.Context) {
	var heads []ChainHead
	if err := a.db.WithContext(ctx).Find(&heads).Error; err != nil {
		return
	}
	for i := range heads {
		h := &heads[i]
		var anchoredThrough int64
		var last AuditAnchor
		err := a.db.WithContext(ctx).
			Where("tenant_id = ? AND chain_class = ?", h.TenantID, h.ChainClass).
			Order("to_seq desc").First(&last).Error
		switch {
		case err == nil:
			anchoredThrough = last.ToSeq
		case errors.Is(err, gorm.ErrRecordNotFound):
			// Never anchored: the whole chain is the lag.
		default:
			continue
		}
		metrics.AuditAnchorLag(
			strconv.FormatInt(h.TenantID, 10), h.ChainClass, h.LastSeq-anchoredThrough)
	}
}

// AnchorAll anchors every chain that has a head. Returns the number of new anchors.
func (a *Anchorer) AnchorAll(ctx context.Context) (int, error) {
	var heads []ChainHead
	if err := a.db.WithContext(ctx).Find(&heads).Error; err != nil {
		return 0, err
	}
	var n int
	for _, h := range heads {
		got, err := a.AnchorChain(ctx, h.TenantID, h.ChainClass)
		if err != nil {
			return n, err
		}
		if got != nil {
			n++
		}
	}
	return n, nil
}

// Run ticks AnchorAll every interval until ctx is cancelled. Single-writer:
// run exactly one of these per process (mirrors Chainer.Run's invariant).
func (a *Anchorer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := a.AnchorAll(ctx); err != nil {
			a.logger.Warn("audit anchorer: batch failed", zap.Error(err))
		}
		// Reported after the attempt, and unconditionally: when anchoring is
		// failing is exactly when the lag needs to be visible.
		a.reportLag(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

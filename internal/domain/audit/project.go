package audit

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"crypto/sha256"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Rebuilding mxid_audit_log from the ledger.
//
// The two tables are not, and cannot be, mirrors of each other. The ledger holds
// every state-changing event, under hash chain and anchor. mxid_audit_log holds
// those PLUS read/access events (org.read, app.launched, the api.* catch-all)
// which are deliberately not chained: they change nothing, and chaining them
// would multiply ledger volume for events that carry no evidence.
//
// So the honest statement of the relationship is:
//
//	ledger      = every event that changed state          (evidence)
//	audit_log   = that, projected, plus read telemetry    (operational view)
//
// Which makes mxid_audit_log disposable in the way that matters. It is
// aggressively partition-pruned by retention, and if a partition is dropped —
// or the whole table is lost — every evidence-bearing row in it can be
// reconstructed from the ledger. What cannot be reconstructed is the read
// telemetry, and that is a deliberate trade rather than an accident.

// projectedID derives a stable, non-colliding id for a reconstructed row.
//
// Negative on purpose. Snowflake ids are positive, so a negative id can never
// collide with a natively-written row, and it marks the row as reconstructed
// without needing an extra column. Deriving it from (tenant, class, seq) rather
// than generating a fresh one makes a rebuild idempotent: replaying the same
// range twice produces the same ids and the second pass is a no-op.
func projectedID(tenantID int64, class string, seq int64) int64 {
	h := sha256.New()
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(tenantID))
	h.Write(b8[:])
	h.Write([]byte(class))
	binary.BigEndian.PutUint64(b8[:], uint64(seq))
	h.Write(b8[:])
	sum := h.Sum(nil)
	// Mask to 62 bits so negation cannot overflow, then negate.
	v := int64(binary.BigEndian.Uint64(sum[:8]) & 0x3FFFFFFFFFFFFFFF)
	if v == 0 {
		v = 1
	}
	return -v
}

// RebuildResult reports what one rebuild pass wrote.
type RebuildResult struct {
	EntriesRead int
	RowsWritten int64
	ThroughSeq  int64
}

// RebuildFromLedger replays chain entries for (tenantID, class) with seq greater
// than afterSeq, projecting each into mxid_audit_log.
//
// Streams in bounded batches for the same reason verification does: the ledger
// is sized by total history, and a rebuild that has to hold it all in memory is
// a rebuild that stops working exactly when it is needed.
//
// Existing rows are left alone (ON CONFLICT DO NOTHING). A rebuild is a repair
// operation and must be safe to run against a table that is only partly missing
// — the common case, since retention drops whole partitions and leaves the rest.
func RebuildFromLedger(ctx context.Context, db *gorm.DB, tenantID int64, class string, afterSeq int64) (RebuildResult, error) {
	var res RebuildResult
	cursor := afterSeq

	for {
		var batch []AuditEntry
		if err := db.WithContext(ctx).
			Where("tenant_id = ? AND chain_class = ? AND seq > ?", tenantID, class, cursor).
			Order("seq asc").Limit(verifyBatchSize).Find(&batch).Error; err != nil {
			return res, fmt.Errorf("read ledger: %w", err)
		}
		if len(batch) == 0 {
			return res, nil
		}

		rows := make([]AuditLog, 0, len(batch))
		for i := range batch {
			row, ok, err := projectEntry(&batch[i])
			if err != nil {
				return res, err
			}
			if ok {
				rows = append(rows, row)
			}
		}
		res.EntriesRead += len(batch)

		if len(rows) > 0 {
			out := db.WithContext(ctx).
				Clauses(clause.OnConflict{DoNothing: true}).
				CreateInBatches(rows, len(rows))
			if out.Error != nil {
				return res, fmt.Errorf("write projection: %w", out.Error)
			}
			res.RowsWritten += out.RowsAffected
		}
		cursor = batch[len(batch)-1].Seq
		res.ThroughSeq = cursor
	}
}

// projectEntry maps one ledger entry to its audit_log shape. Returns ok=false
// for an entry that carries no projectable payload.
func projectEntry(e *AuditEntry) (AuditLog, bool, error) {
	var p ChainPayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return AuditLog{}, false, fmt.Errorf("decode payload tenant=%d class=%s seq=%d: %w",
			e.TenantID, e.ChainClass, e.Seq, err)
	}
	if p.EventType == "" {
		return AuditLog{}, false, nil
	}

	occurred, err := time.Parse(time.RFC3339, p.OccurredAt)
	if err != nil {
		// The ledger's timestamp is the authoritative one; without it the row
		// cannot be placed in the right partition, so skipping beats guessing.
		return AuditLog{}, false, nil
	}

	row := AuditLog{
		ID:          projectedID(e.TenantID, e.ChainClass, e.Seq),
		TenantID:    p.TenantID,
		ActorType:   p.ActorType,
		EventType:   p.EventType,
		EventStatus: eventStatusFromDetail(p.Detail),
		CreatedAt:   occurred,
	}
	if p.ActorID != 0 {
		row.ActorID = &p.ActorID
	}
	if p.ResourceID != 0 {
		row.ResourceID = &p.ResourceID
	}
	// Only set when recorded. A v1 payload carries none of these, and writing ""
	// would assert an empty name rather than an unknown one.
	row.ActorName = nonEmpty(p.ActorName)
	row.ResourceType = nonEmpty(p.ResourceType)
	row.ResourceName = nonEmpty(p.ResourceName)
	row.IP = nonEmpty(p.IP)
	row.UserAgent = nonEmpty(p.UserAgent)
	row.GeoCity = nonEmpty(p.GeoCity)
	row.GeoCountry = nonEmpty(p.GeoCountry)
	row.SessionID = nonEmpty(p.SessionID)

	// Always write an explicit object rather than leaving the column to its
	// default. Relying on the default makes the reconstructed row depend on DDL
	// that differs by backend, and leaves the field NULL-ish in a column the
	// readers treat as always-present JSON.
	row.Detail = json.RawMessage("{}")
	if len(p.Detail) > 0 {
		if b, err := json.Marshal(p.Detail); err == nil {
			row.Detail = b
		}
	}
	return row, true, nil
}

// eventStatusFromDetail recovers the success/failure flag the bridge folded
// into detail. Absent means success: the ORM capture path only ever runs on a
// write that committed.
func eventStatusFromDetail(detail map[string]any) int {
	v, ok := detail["event_status"]
	if !ok {
		return EventStatusSuccess
	}
	switch n := v.(type) {
	case float64: // JSON numbers decode to float64
		return int(n)
	case int:
		return n
	default:
		return EventStatusSuccess
	}
}

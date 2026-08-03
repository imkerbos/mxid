package audit

import "time"

// AuditAnchor records one signed Merkle anchor over entries [FromSeq, ToSeq] of
// a (TenantID, ChainClass) chain.
type AuditAnchor struct {
	ID         int64  `gorm:"column:id;primaryKey"`
	TenantID   int64  `gorm:"column:tenant_id;not null;uniqueIndex:uq_audit_anchor_span,priority:1"`
	ChainClass string `gorm:"column:chain_class;not null;size:16;uniqueIndex:uq_audit_anchor_span,priority:2"`
	FromSeq    int64  `gorm:"column:from_seq;not null;uniqueIndex:uq_audit_anchor_span,priority:3"`
	ToSeq      int64  `gorm:"column:to_seq;not null;uniqueIndex:uq_audit_anchor_span,priority:4"`
	MerkleRoot []byte `gorm:"column:merkle_root;not null"`
	Signature  []byte `gorm:"column:signature;not null"`
	KeyID      string `gorm:"column:key_id;not null;size:64"`
	// Version selects the signature preimage. Rows written before anchors were
	// chained are 1; current ones are 2. See VerifyAnchorSig.
	Version int16 `gorm:"column:version;not null;default:1"`
	// PrevAnchorHash commits to the preceding anchor of the same chain, which is
	// what makes deleting an anchor row detectable. Nil for the first anchor of
	// a chain and for every version-1 row.
	PrevAnchorHash []byte    `gorm:"column:prev_anchor_hash"`
	ExternalURI    string    `gorm:"column:external_uri;not null"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
}

func (AuditAnchor) TableName() string { return "mxid_audit_anchor" }

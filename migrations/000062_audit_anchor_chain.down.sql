-- Dropping these columns downgrades every version-2 anchor to an unverifiable
-- state: its signature covers prev_anchor_hash, so without the column the
-- preimage cannot be reconstructed. Rolling back is therefore only safe if the
-- anchors written since the up-migration are expendable.
DROP INDEX IF EXISTS idx_audit_anchor_chain;

ALTER TABLE mxid_audit_anchor
    DROP COLUMN IF EXISTS prev_anchor_hash,
    DROP COLUMN IF EXISTS version;

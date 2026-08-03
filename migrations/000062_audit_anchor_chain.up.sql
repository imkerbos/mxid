-- Link the audit anchors into a hash chain of their own.
--
-- Until now each anchor stood alone: it signed (tenant, class, from_seq,
-- to_seq, merkle_root), which proves the RANGE was not altered but says nothing
-- about the anchor's place in the sequence. Deleting a whole anchor row was
-- therefore invisible to online verification — VerifyAnchors could only report
-- a coverage gap, and could not report anything at all if the most recent
-- anchors were the ones removed, because an un-anchored tail looks identical to
-- a deleted one.
--
-- The external sink used to be the answer to that. It is now off by default,
-- because a per-pod file was never actually outside the database's trust
-- domain. Chaining the anchors puts the guarantee back where it can be relied
-- on: anchor N commits to anchor N-1, so removing an anchor breaks the
-- reference held by its successor, and the break is signed.
--
-- version discriminates the signature preimage so anchors written before this
-- migration keep verifying under the format they were signed with. Existing
-- rows are version 1 and carry no prev_anchor_hash; new ones are version 2.
ALTER TABLE mxid_audit_anchor
    ADD COLUMN IF NOT EXISTS version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS prev_anchor_hash BYTEA;

-- Walking the chain means repeatedly asking for the anchor that precedes a
-- given from_seq, per (tenant, class).
CREATE INDEX IF NOT EXISTS idx_audit_anchor_chain
    ON mxid_audit_anchor (tenant_id, chain_class, to_seq DESC);

COMMENT ON COLUMN mxid_audit_anchor.version IS
    'Signature preimage version. 1 = (tenant,class,from,to,root); 2 = adds prev_anchor_hash.';
COMMENT ON COLUMN mxid_audit_anchor.prev_anchor_hash IS
    'SHA-256 of the preceding anchor''s signature preimage. NULL for the first anchor of a chain and for all version-1 rows.';

-- One anchor per (tenant_id, chain_class, from_seq, to_seq) span. Without this,
-- two replicas racing the anchorer (or a failover overlap) could each compute the
-- identical signed anchor for the same gap and both insert it (id is a fresh
-- Snowflake, so a plain PK never rejects the duplicate), polluting the
-- tamper-evident anchor ledger with duplicate rows. The advisory-lock leader
-- makes the race rare; this constraint is the last-resort guard.
-- Upgrade safety: drop any pre-existing duplicate anchors for the same span
-- BEFORE creating the index, so an upgrade over dirty data heals instead of
-- failing the migration. The old anchorer had no dedup and could run on multiple
-- replicas, so duplicate rows may exist. Duplicates are deterministic copies
-- (a given span always yields the same merkle_root + Ed25519 signature), so
-- keeping the earliest row (lowest id) loses no coverage or tamper-evidence.
-- mxid_audit_anchor has NO append-only trigger (that guards mxid_audit_entry
-- only), so DELETE here is permitted.
DELETE FROM mxid_audit_anchor a
USING mxid_audit_anchor b
WHERE a.tenant_id = b.tenant_id
  AND a.chain_class = b.chain_class
  AND a.from_seq = b.from_seq
  AND a.to_seq = b.to_seq
  AND a.id > b.id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_anchor_span
    ON mxid_audit_anchor (tenant_id, chain_class, from_seq, to_seq);

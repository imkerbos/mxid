-- Make the ledger prunable without making it rewritable.
--
-- mxid_audit_entry is append-only and never deleted, so it grows without bound:
-- at 50k business writes a day it is ~150k entries a day, and nothing in the
-- system ever removes one. That was not an oversight in the retention job. It
-- was structural: verification could only start at seq 1 against the genesis
-- hash, so a missing row was indistinguishable from a deleted one, and removing
-- anything would have made the chain unverifiable.
--
-- Checkpoints remove that constraint. A checkpoint states, under signature,
-- "entries up to and including pruned_through_seq existed and hashed to
-- prev_hash", which is exactly what verification needs to resume mid-chain. The
-- pruned range remains attested by its anchor (a few hundred bytes) long after
-- the entries themselves are gone.

CREATE TABLE IF NOT EXISTS mxid_audit_checkpoint (
    id                 BIGINT       PRIMARY KEY,
    tenant_id          BIGINT       NOT NULL,
    chain_class        VARCHAR(16)  NOT NULL,
    -- Highest seq that has been pruned. Verification resumes at seq+1.
    pruned_through_seq BIGINT       NOT NULL,
    -- entry_hash of pruned_through_seq: the link the next surviving entry's
    -- prev_hash must match.
    prev_hash          BYTEA        NOT NULL,
    signature          BYTEA        NOT NULL,
    key_id             VARCHAR(64)  NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- One checkpoint per chain: pruning only ever moves the floor forward, so a
    -- new prune replaces the previous checkpoint rather than accumulating.
    CONSTRAINT uq_audit_checkpoint_chain UNIQUE (tenant_id, chain_class)
);

COMMENT ON TABLE mxid_audit_checkpoint IS
    'Signed floor for each audit chain. Entries at or below pruned_through_seq have been removed; verification resumes from prev_hash.';

-- Replace the append-only trigger with one that still forbids UPDATE outright
-- but allows DELETE through a single, explicit gate.
--
-- The distinction is the point. Rewriting history has no legitimate caller, so
-- UPDATE stays unconditionally refused. Deleting an already-checkpointed prefix
-- is a sanctioned lifecycle operation, and the alternative — dropping the
-- trigger for the duration of a prune — would open a window in which the
-- append-only guarantee does not hold at all.
--
-- The gate is a transaction-local setting, so it cannot leak past the
-- transaction that sets it, and every prune shows up as the deliberate act of
-- code that set it. It is NOT a defence against someone with direct database
-- access: they could set it themselves, just as they could drop the trigger.
-- Its job is the same as before — stopping the application, an ORM mistake, or
-- a careless operator from destroying evidence — and that job it still does.
CREATE OR REPLACE FUNCTION mxid_audit_entry_append_only()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('mxid.audit_prune', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'mxid_audit_entry is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

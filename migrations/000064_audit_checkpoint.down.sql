-- Restoring the unconditional trigger is safe; dropping the checkpoints is not.
-- Any chain that has already been pruned becomes unverifiable without its
-- checkpoint, because verification would fall back to starting at seq 1 and
-- find the pruned prefix missing. Roll back only if nothing has been pruned.
CREATE OR REPLACE FUNCTION mxid_audit_entry_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'mxid_audit_entry is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TABLE IF EXISTS mxid_audit_checkpoint;

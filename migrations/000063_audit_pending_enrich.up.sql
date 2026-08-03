-- Carry the human-readable identifiers into the ledger.
--
-- The chain records actor_id but not actor_name, and resource_id but not
-- resource_name; geo was never carried at all. Those fields existed only in
-- mxid_audit_log, which is retention-purged — so after RetentionDays the
-- product permanently loses WHO did something (an id whose user row may since
-- have been renamed or deleted) and from WHERE, while keeping the
-- tamper-evident record of WHAT.
--
-- That split also blocks the larger goal: mxid_audit_log cannot become a
-- rebuildable projection of the ledger while the ledger holds strictly less
-- than the projection does.
--
-- Nullable with no default and no backfill: these columns are unknown for
-- existing rows, and writing '' would assert that the name was empty rather
-- than unrecorded. Payload version (see ChainPayload) is what lets a reader
-- tell those apart.
ALTER TABLE mxid_audit_pending
    ADD COLUMN IF NOT EXISTS actor_name    VARCHAR(128),
    ADD COLUMN IF NOT EXISTS resource_name VARCHAR(256),
    ADD COLUMN IF NOT EXISTS geo_city      VARCHAR(64),
    ADD COLUMN IF NOT EXISTS geo_country   VARCHAR(64);

COMMENT ON COLUMN mxid_audit_pending.actor_name IS
    'Display name of the actor at the time of the event. NULL = not recorded (row predates enrichment).';
COMMENT ON COLUMN mxid_audit_pending.resource_name IS
    'Human-readable name of the affected resource at the time of the event.';

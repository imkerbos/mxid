-- mxid_audit_pending is a queue that the chainer drains, so rolling back only
-- loses enrichment for rows not yet chained. Entries already written carry the
-- fields inside their signed payload and are unaffected.
ALTER TABLE mxid_audit_pending
    DROP COLUMN IF EXISTS geo_country,
    DROP COLUMN IF EXISTS geo_city,
    DROP COLUMN IF EXISTS resource_name,
    DROP COLUMN IF EXISTS actor_name;

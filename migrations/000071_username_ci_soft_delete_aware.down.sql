-- Back to 000070's shape (covering soft-deleted rows). Deliberately NOT a
-- no-op: a down migration has to land on the state the previous version
-- expects, even when that state is the one being corrected.
DROP INDEX IF EXISTS uq_mxid_user_tenant_username_lower;

CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_user_tenant_username_lower
    ON mxid_user (tenant_id, lower(username));

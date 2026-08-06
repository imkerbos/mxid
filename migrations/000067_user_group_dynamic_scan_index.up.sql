-- Index the columns the dynamic-group reconcile scans on.
--
-- runDynamicGroupReconcile lists every dynamic group in the tenant on startup
-- and every 30 minutes:
--
--   SELECT id FROM mxid_user_group WHERE tenant_id = ? AND type = 2
--
-- The table's only index is UNIQUE (tenant_id, code). `type` is not in it, and
-- a leading-column-only match still has to filter every row of the tenant, so
-- this was a scan of the whole group table. Harmless with a handful of groups —
-- which is why it showed up as a 200ms warning on a new install and nothing
-- worse — but it grows with the number of groups and runs on a schedule.
--
-- Partial on deleted_at because the query only ever wants live rows and the
-- soft-deleted ones are dead weight in the index.
CREATE INDEX IF NOT EXISTS idx_user_group_tenant_type
    ON mxid_user_group (tenant_id, type) WHERE deleted_at IS NULL;

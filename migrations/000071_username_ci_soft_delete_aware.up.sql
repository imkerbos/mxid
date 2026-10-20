-- Make the case-insensitive username index soft-delete-aware.
--
-- 000070 created it without a WHERE clause, which quietly reintroduced the
-- exact defect 000047 had removed: a soft-deleted account kept holding its
-- username forever, so the name could never be reused. The failure shape is
-- the one 000047 describes — the app-level GetByUsername pre-check excludes
-- soft-deleted rows, so it passes, and the INSERT then hits the index and
-- surfaces as a raw 23505 turned into a generic 500 rather than a clean
-- "username exists".
--
-- 000070's intent was only to make the EXISTING uniqueness case-insensitive.
-- Scope was supposed to mirror idx_user_tenant_username; it did not.
DROP INDEX IF EXISTS uq_mxid_user_tenant_username_lower;

CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_user_tenant_username_lower
    ON mxid_user (tenant_id, lower(username)) WHERE deleted_at IS NULL;

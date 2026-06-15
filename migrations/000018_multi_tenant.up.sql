-- L1 多租户 + L2 共享应用 schema 改造（rev 2 — handle existing PG constraints）。
--
-- Idempotent: 每个 ALTER 都用 IF NOT EXISTS / DROP IF EXISTS。

ALTER TABLE mxid_app
    ADD COLUMN IF NOT EXISTS scope SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS subject_strategy VARCHAR(32) NOT NULL DEFAULT 'username';

-- Drop the old (tenant_id, code) UNIQUE constraint so tenant_id can become NULLABLE.
ALTER TABLE mxid_app DROP CONSTRAINT IF EXISTS mxid_app_tenant_id_code_key;

-- Now drop NOT NULL on tenant_id (shared apps will have NULL).
ALTER TABLE mxid_app ALTER COLUMN tenant_id DROP NOT NULL;

-- Recreate uniqueness with COALESCE so shared apps (NULL tenant_id) still get a stable key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_tenant_code
    ON mxid_app(COALESCE(tenant_id, 0), code)
    WHERE deleted_at IS NULL;

-- App account per (app_id, tenant_id, user_id) so shared apps see two tenants'
-- same user_id as separate accounts.
ALTER TABLE mxid_app_account
    ADD COLUMN IF NOT EXISTS tenant_id BIGINT;

UPDATE mxid_app_account SET tenant_id = 1 WHERE tenant_id IS NULL;

DROP INDEX IF EXISTS idx_app_tenant_code;
ALTER TABLE mxid_app DROP COLUMN IF EXISTS subject_strategy;
ALTER TABLE mxid_app DROP COLUMN IF EXISTS scope;
UPDATE mxid_app SET tenant_id = 1 WHERE tenant_id IS NULL;
ALTER TABLE mxid_app ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE mxid_app_account DROP COLUMN IF EXISTS tenant_id;

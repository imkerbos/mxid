ALTER TABLE mxid_app_role_binding DROP CONSTRAINT IF EXISTS chk_mxid_app_role_binding_target;
DROP INDEX IF EXISTS uq_mxid_app_role_binding_target_subject;
DROP INDEX IF EXISTS idx_mxid_app_role_binding_group;
ALTER TABLE mxid_app_role_binding DROP COLUMN IF EXISTS app_group_id;
ALTER TABLE mxid_app_role_binding ALTER COLUMN app_id SET NOT NULL;

ALTER TABLE mxid_app_role DROP CONSTRAINT IF EXISTS chk_mxid_app_role_target;
DROP INDEX IF EXISTS uq_mxid_app_role_target_code;
DROP INDEX IF EXISTS idx_mxid_app_role_group;
ALTER TABLE mxid_app_role DROP COLUMN IF EXISTS app_group_id;
ALTER TABLE mxid_app_role ALTER COLUMN app_id SET NOT NULL;

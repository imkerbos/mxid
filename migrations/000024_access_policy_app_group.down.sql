ALTER TABLE mxid_app_access_policy DROP CONSTRAINT IF EXISTS chk_mxid_app_access_policy_target;
DROP INDEX IF EXISTS uq_mxid_app_access_policy_target_subject;
DROP INDEX IF EXISTS idx_mxid_app_access_policy_app_group;
ALTER TABLE mxid_app_access_policy DROP COLUMN IF EXISTS app_group_id;
ALTER TABLE mxid_app_access_policy ALTER COLUMN app_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_app_access_policy_app_subject
    ON mxid_app_access_policy(app_id, tenant_id, subject_type, subject_id);

-- Drop the FK CASCADE constraints added in the up migration. The orphan/soft-
-- deleted rows purged in step 1-2 cannot be restored (they were already logically
-- deleted); that is acceptable for a down migration.

BEGIN;

ALTER TABLE mxid_app_access_policy
  DROP CONSTRAINT IF EXISTS fk_app_access_policy_app,
  DROP CONSTRAINT IF EXISTS fk_app_access_policy_app_group;

ALTER TABLE mxid_app_role
  DROP CONSTRAINT IF EXISTS fk_app_role_app;

ALTER TABLE mxid_app_role_binding
  DROP CONSTRAINT IF EXISTS fk_app_role_binding_app,
  DROP CONSTRAINT IF EXISTS fk_app_role_binding_role;

ALTER TABLE mxid_app_provisioning
  DROP CONSTRAINT IF EXISTS fk_app_provisioning_app;

COMMIT;

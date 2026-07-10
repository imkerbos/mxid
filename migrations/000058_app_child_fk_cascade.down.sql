-- Drop the named ON DELETE CASCADE FKs added by the up migration. Purged orphan
-- rows are not restored (they were already logically deleted). The original
-- inline auto-named FKs from 000004/000011/000028 are NOT recreated here — a
-- SQL-migrated DB that never lost them keeps behaving; an AutoMigrate DB simply
-- returns to its prior (FK-less) state.

BEGIN;

ALTER TABLE mxid_app_group_rel
  DROP CONSTRAINT IF EXISTS fk_app_group_rel_app,
  DROP CONSTRAINT IF EXISTS fk_app_group_rel_group;

ALTER TABLE mxid_app_access
  DROP CONSTRAINT IF EXISTS fk_app_access_app;

ALTER TABLE mxid_app_account
  DROP CONSTRAINT IF EXISTS fk_app_account_app,
  DROP CONSTRAINT IF EXISTS fk_app_account_user;

ALTER TABLE mxid_app_cert
  DROP CONSTRAINT IF EXISTS fk_app_cert_app;

ALTER TABLE mxid_user_app_consent
  DROP CONSTRAINT IF EXISTS fk_user_app_consent_app,
  DROP CONSTRAINT IF EXISTS fk_user_app_consent_user;

ALTER TABLE mxid_user_app_favorite
  DROP CONSTRAINT IF EXISTS fk_user_app_favorite_app,
  DROP CONSTRAINT IF EXISTS fk_user_app_favorite_user;

COMMIT;

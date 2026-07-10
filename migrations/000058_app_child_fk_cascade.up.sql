-- Heal the app child tables whose ON DELETE CASCADE never took effect on
-- AutoMigrate-provisioned databases.
--
-- Background: migration 000004/000011/000028 declare these FKs *inline*
--   (app_id BIGINT NOT NULL REFERENCES mxid_app(id) ON DELETE CASCADE)
-- so a SQL-migrated DB cascades correctly. But databases first provisioned via
-- GORM AutoMigrate never got those inline FKs at all — GORM does not emit
-- ON DELETE CASCADE. On such a DB, hard-deleting an app SUCCEEDS but leaves its
-- children behind as orphans (no FK to block or cascade). That is the root of
-- the portal "deleted app still counted in its group" bug: an orphan
-- mxid_app_group_rel row survived the app delete and inflated the sidebar count.
--
-- migration 000056 healed the association tables it knew about but MISSED the
-- inline-FK app children below. This migration finishes the job: purge existing
-- orphans, then (re)assert a NAMED ON DELETE CASCADE FK so both DB lineages
-- converge on exactly one cascade FK and future deletes clean up server-side.
--
-- Idempotent: drops both the Postgres auto-name (<table>_<col>_fkey, present on
-- SQL-migrated DBs) and our fk_* name before adding, so re-runs and either
-- lineage are safe.

BEGIN;

-- 1. Purge existing orphans (parent already gone). Must precede ADD CONSTRAINT,
--    which would otherwise fail validation against the surviving orphans.
DELETE FROM mxid_app_group_rel   r WHERE NOT EXISTS (SELECT 1 FROM mxid_app       a WHERE a.id = r.app_id);
DELETE FROM mxid_app_group_rel   r WHERE NOT EXISTS (SELECT 1 FROM mxid_app_group g WHERE g.id = r.group_id);
DELETE FROM mxid_app_access      t WHERE NOT EXISTS (SELECT 1 FROM mxid_app       a WHERE a.id = t.app_id);
DELETE FROM mxid_app_account     t WHERE NOT EXISTS (SELECT 1 FROM mxid_app       a WHERE a.id = t.app_id);
DELETE FROM mxid_app_account     t WHERE NOT EXISTS (SELECT 1 FROM mxid_user      u WHERE u.id = t.user_id);
DELETE FROM mxid_app_cert        t WHERE NOT EXISTS (SELECT 1 FROM mxid_app       a WHERE a.id = t.app_id);
DELETE FROM mxid_user_app_consent  t WHERE NOT EXISTS (SELECT 1 FROM mxid_app     a WHERE a.id = t.app_id);
DELETE FROM mxid_user_app_consent  t WHERE NOT EXISTS (SELECT 1 FROM mxid_user    u WHERE u.id = t.user_id);
DELETE FROM mxid_user_app_favorite t WHERE NOT EXISTS (SELECT 1 FROM mxid_app     a WHERE a.id = t.app_id);
DELETE FROM mxid_user_app_favorite t WHERE NOT EXISTS (SELECT 1 FROM mxid_user    u WHERE u.id = t.user_id);

-- 2. (Re)assert named ON DELETE CASCADE FKs.

ALTER TABLE mxid_app_group_rel
  DROP CONSTRAINT IF EXISTS mxid_app_group_rel_app_id_fkey,
  DROP CONSTRAINT IF EXISTS mxid_app_group_rel_group_id_fkey,
  DROP CONSTRAINT IF EXISTS fk_app_group_rel_app,
  DROP CONSTRAINT IF EXISTS fk_app_group_rel_group,
  ADD  CONSTRAINT fk_app_group_rel_app   FOREIGN KEY (app_id)   REFERENCES mxid_app(id)       ON DELETE CASCADE,
  ADD  CONSTRAINT fk_app_group_rel_group FOREIGN KEY (group_id) REFERENCES mxid_app_group(id) ON DELETE CASCADE;

ALTER TABLE mxid_app_access
  DROP CONSTRAINT IF EXISTS mxid_app_access_app_id_fkey,
  DROP CONSTRAINT IF EXISTS fk_app_access_app,
  ADD  CONSTRAINT fk_app_access_app FOREIGN KEY (app_id) REFERENCES mxid_app(id) ON DELETE CASCADE;

ALTER TABLE mxid_app_account
  DROP CONSTRAINT IF EXISTS mxid_app_account_app_id_fkey,
  DROP CONSTRAINT IF EXISTS mxid_app_account_user_id_fkey,
  DROP CONSTRAINT IF EXISTS fk_app_account_app,
  DROP CONSTRAINT IF EXISTS fk_app_account_user,
  ADD  CONSTRAINT fk_app_account_app  FOREIGN KEY (app_id)  REFERENCES mxid_app(id)  ON DELETE CASCADE,
  ADD  CONSTRAINT fk_app_account_user FOREIGN KEY (user_id) REFERENCES mxid_user(id) ON DELETE CASCADE;

ALTER TABLE mxid_app_cert
  DROP CONSTRAINT IF EXISTS mxid_app_cert_app_id_fkey,
  DROP CONSTRAINT IF EXISTS fk_app_cert_app,
  ADD  CONSTRAINT fk_app_cert_app FOREIGN KEY (app_id) REFERENCES mxid_app(id) ON DELETE CASCADE;

ALTER TABLE mxid_user_app_consent
  DROP CONSTRAINT IF EXISTS mxid_user_app_consent_app_id_fkey,
  DROP CONSTRAINT IF EXISTS mxid_user_app_consent_user_id_fkey,
  DROP CONSTRAINT IF EXISTS fk_user_app_consent_app,
  DROP CONSTRAINT IF EXISTS fk_user_app_consent_user,
  ADD  CONSTRAINT fk_user_app_consent_app  FOREIGN KEY (app_id)  REFERENCES mxid_app(id)  ON DELETE CASCADE,
  ADD  CONSTRAINT fk_user_app_consent_user FOREIGN KEY (user_id) REFERENCES mxid_user(id) ON DELETE CASCADE;

ALTER TABLE mxid_user_app_favorite
  DROP CONSTRAINT IF EXISTS mxid_user_app_favorite_app_id_fkey,
  DROP CONSTRAINT IF EXISTS mxid_user_app_favorite_user_id_fkey,
  DROP CONSTRAINT IF EXISTS fk_user_app_favorite_app,
  DROP CONSTRAINT IF EXISTS fk_user_app_favorite_user,
  ADD  CONSTRAINT fk_user_app_favorite_app  FOREIGN KEY (app_id)  REFERENCES mxid_app(id)  ON DELETE CASCADE,
  ADD  CONSTRAINT fk_user_app_favorite_user FOREIGN KEY (user_id) REFERENCES mxid_user(id) ON DELETE CASCADE;

COMMIT;

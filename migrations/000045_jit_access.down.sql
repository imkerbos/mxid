-- Delete role_permission rows created by this migration's up.sql.
-- NOTE: id=4200 (auditor role 4 -> audit.read permission 200) belongs to
-- migration 000016 and must NOT be deleted here (it is idempotent in our up.sql).
DELETE FROM mxid_role_permission WHERE id IN (904500021, 904500022);
DELETE FROM mxid_role WHERE id IN (904500011, 904500012);
DELETE FROM mxid_permission WHERE id IN (904500001, 904500002, 904500003);
DROP TABLE IF EXISTS mxid_access_request;
DROP TABLE IF EXISTS mxid_access_eligibility;
DROP INDEX IF EXISTS idx_app_role_binding_expiry;
DROP INDEX IF EXISTS idx_role_binding_expiry;
ALTER TABLE mxid_app_role_binding DROP COLUMN IF EXISTS grant_id, DROP COLUMN IF EXISTS expires_at, DROP COLUMN IF EXISTS status;
ALTER TABLE mxid_role_binding DROP COLUMN IF EXISTS grant_id, DROP COLUMN IF EXISTS expires_at, DROP COLUMN IF EXISTS status;

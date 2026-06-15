DROP INDEX IF EXISTS idx_mxid_user_is_super_admin;
ALTER TABLE mxid_user DROP COLUMN IF EXISTS is_super_admin;

DROP INDEX IF EXISTS idx_app_group_parent;
ALTER TABLE mxid_app_group DROP COLUMN IF EXISTS parent_id;

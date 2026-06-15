DROP INDEX IF EXISTS idx_group_rule_status;
DROP TABLE IF EXISTS mxid_user_group_rule;
ALTER TABLE mxid_user_group DROP COLUMN IF EXISTS type;

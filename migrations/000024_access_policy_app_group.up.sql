-- Extend access policy to cover app groups, not just individual apps.
--
-- Model: one row owns either an app or an app group, not both.
-- Effective policy for any app = its own rows UNION all rows owned by
-- any app_group it belongs to (mxid_app_group_rel). Deny still wins.
--
-- app_id is relaxed to nullable + a CHECK to enforce exactly-one-of.
-- Old rows are unaffected (NOT NULL relaxed → NULL allowed but existing
-- rows keep their value).
ALTER TABLE mxid_app_access_policy ALTER COLUMN app_id DROP NOT NULL;

ALTER TABLE mxid_app_access_policy
    ADD COLUMN IF NOT EXISTS app_group_id BIGINT;

-- Exactly one of (app_id, app_group_id) must be set. Postgres treats
-- NULL ≠ NULL in CHECK so we count non-null columns.
ALTER TABLE mxid_app_access_policy
    DROP CONSTRAINT IF EXISTS chk_mxid_app_access_policy_target;
ALTER TABLE mxid_app_access_policy
    ADD CONSTRAINT chk_mxid_app_access_policy_target
    CHECK (
        (app_id IS NOT NULL AND app_group_id IS NULL) OR
        (app_id IS NULL     AND app_group_id IS NOT NULL)
    );

-- Replace the existing unique index with one that covers both target types.
-- COALESCE(app_id, 0) + COALESCE(app_group_id, 0) keeps uniqueness within
-- whichever bucket the row belongs to.
DROP INDEX IF EXISTS uq_mxid_app_access_policy_app_subject;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_app_access_policy_target_subject
    ON mxid_app_access_policy(
        COALESCE(app_id, 0),
        COALESCE(app_group_id, 0),
        tenant_id,
        subject_type,
        subject_id
    );

CREATE INDEX IF NOT EXISTS idx_mxid_app_access_policy_app_group
    ON mxid_app_access_policy(app_group_id, tenant_id);

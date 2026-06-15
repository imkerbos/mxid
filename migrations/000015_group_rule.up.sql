-- Dynamic group rules.
--
-- A group is now either:
--   type=1 (static)  — members managed manually
--   type=2 (dynamic) — members computed from a rule and refreshed by sync
--
-- Dynamic groups own at most one rule (UNIQUE on group_id). The rule body is
-- a JSON expression; see internal/domain/group/rule.go for the DSL shape.

ALTER TABLE mxid_user_group
    ADD COLUMN IF NOT EXISTS type SMALLINT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS mxid_user_group_rule (
    id                 BIGINT PRIMARY KEY,
    group_id           BIGINT       NOT NULL UNIQUE REFERENCES mxid_user_group(id) ON DELETE CASCADE,
    expr               JSONB        NOT NULL,
    status             SMALLINT     NOT NULL DEFAULT 1, -- 1=enabled 2=paused
    last_sync_at       TIMESTAMPTZ,
    last_sync_added    INT          NOT NULL DEFAULT 0,
    last_sync_removed  INT          NOT NULL DEFAULT 0,
    last_sync_error    TEXT,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_group_rule_status ON mxid_user_group_rule(status);

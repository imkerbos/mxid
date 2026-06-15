-- App access policy.
--
-- Authorization layer for "who can use which app". Without entries,
-- an app is DENIED to everyone. The very first deploy / migration
-- seeds a `public` entry for already-existing apps so the upgrade
-- doesn't lock everyone out — admins can tighten later.
--
-- subject_type values:
--   public  →  no subject_id, matches all authenticated users
--   user    →  subject_id = mxid_user.id
--   group   →  subject_id = mxid_user_group.id
--   org     →  subject_id = mxid_org.id (with subtree match)
--   role    →  subject_id = mxid_role.id
--
-- effect:
--   allow  →  grant access (default)
--   deny   →  explicit deny, OVERRIDES any allow (used for revocation
--             without removing a group membership)
--
-- Composite uniqueness lets the same subject be referenced once per app
-- per tenant, and lets shared apps have different policies per tenant.
CREATE TABLE IF NOT EXISTS mxid_app_access_policy (
    id           BIGINT       PRIMARY KEY,
    app_id       BIGINT       NOT NULL,
    tenant_id    BIGINT       NOT NULL DEFAULT 0,
    subject_type VARCHAR(16)  NOT NULL,
    subject_id   BIGINT       NOT NULL DEFAULT 0,
    effect       VARCHAR(8)   NOT NULL DEFAULT 'allow',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by   BIGINT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_app_access_policy_app_subject
    ON mxid_app_access_policy(app_id, tenant_id, subject_type, subject_id);

CREATE INDEX IF NOT EXISTS idx_mxid_app_access_policy_app_tenant
    ON mxid_app_access_policy(app_id, tenant_id);

-- Backfill: every existing app gets a `public` allow so this upgrade is
-- non-breaking. Admins reduce scope later via console UI.
INSERT INTO mxid_app_access_policy (id, app_id, tenant_id, subject_type, subject_id, effect)
SELECT
    (extract(epoch from now())::bigint * 1000 + a.id),  -- pseudo id; never collides with snowflake
    a.id,
    COALESCE(a.tenant_id, 0),
    'public',
    0,
    'allow'
FROM mxid_app a
WHERE a.deleted_at IS NULL
ON CONFLICT DO NOTHING;

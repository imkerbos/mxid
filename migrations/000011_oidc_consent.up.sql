-- =========================================================================
-- OIDC IdP Milestone B — user/app consent persistence.
-- Spec: docs/superpowers/specs/2026-05-23-oidc-idp-complete-design.md §6.4
-- =========================================================================

CREATE TABLE IF NOT EXISTS mxid_user_app_consent (
    id          BIGINT       PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    app_id      BIGINT       NOT NULL REFERENCES mxid_app(id)  ON DELETE CASCADE,
    scopes      TEXT[]       NOT NULL,
    granted_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ,
    UNIQUE (tenant_id, user_id, app_id)
);

COMMENT ON TABLE  mxid_user_app_consent          IS 'OIDC scope-grant ledger; one row per (user, app) pair, regardless of how many scope sets have been granted over time.';
COMMENT ON COLUMN mxid_user_app_consent.scopes   IS 'Latest cumulative set of granted scopes (revocation drops the row or sets revoked_at).';
COMMENT ON COLUMN mxid_user_app_consent.revoked_at IS 'NULL = active. Filled when the user revokes consent via portal.';

CREATE INDEX IF NOT EXISTS idx_user_app_consent_user
    ON mxid_user_app_consent(user_id, revoked_at);

-- =========================================================================
-- OIDC IdP Milestone B prep / C delivery — pairwise subject_type persistence.
--
-- A pairwise subject_type (OIDC Core 1.0 §8.1) gives each RP (or RP sector)
-- a different stable `sub` per user, preventing cross-RP correlation. The
-- pseudo_sub stored here is the value emitted as the JWT `sub` claim to
-- that specific sector.
-- =========================================================================

CREATE TABLE IF NOT EXISTS mxid_user_pairwise_sub (
    id                  BIGINT       PRIMARY KEY,
    user_id             BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    sector_identifier   VARCHAR(512) NOT NULL,
    pseudo_sub          VARCHAR(128) NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, sector_identifier)
);

COMMENT ON TABLE  mxid_user_pairwise_sub                IS 'Per (user, RP sector) pseudo subject. Stable across logins; never recycled.';
COMMENT ON COLUMN mxid_user_pairwise_sub.sector_identifier IS 'Origin (or sector_identifier_uri host) the pseudo_sub is bound to.';
COMMENT ON COLUMN mxid_user_pairwise_sub.pseudo_sub        IS 'Opaque value emitted as the OIDC `sub` claim for the bound sector.';

CREATE INDEX IF NOT EXISTS idx_pairwise_user
    ON mxid_user_pairwise_sub(user_id);

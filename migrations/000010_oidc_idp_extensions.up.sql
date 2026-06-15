-- =========================================================================
-- OIDC IdP Milestone A — application + cert schema extensions
-- Spec: docs/superpowers/specs/2026-05-23-oidc-idp-complete-design.md §12
-- =========================================================================

-- ---------------- mxid_app: new columns -----------------------------------

ALTER TABLE mxid_app
    ADD COLUMN IF NOT EXISTS client_type     VARCHAR(20)  NOT NULL DEFAULT 'web_app',
    ADD COLUMN IF NOT EXISTS home_url        VARCHAR(512),
    ADD COLUMN IF NOT EXISTS is_first_party  BOOLEAN      NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS require_consent BOOLEAN      NOT NULL DEFAULT FALSE;

-- client_secret column now stores bcrypt hash (was previously plaintext in MVP).
-- Expand width to fit bcrypt $2a$12$... (60 chars) plus margin.
ALTER TABLE mxid_app ALTER COLUMN client_secret TYPE VARCHAR(255);
COMMENT ON COLUMN mxid_app.client_secret IS 'bcrypt hash of OIDC client_secret; plaintext returned once on create/rotate';
COMMENT ON COLUMN mxid_app.client_type   IS 'OIDC client classification: web_app | spa | native | m2m';
COMMENT ON COLUMN mxid_app.home_url      IS 'Application landing URL used by portal one-click launch';
COMMENT ON COLUMN mxid_app.is_first_party IS 'First-party apps skip consent by default (Auth0 / Okta convention)';
COMMENT ON COLUMN mxid_app.require_consent IS 'Per-app override; B milestone activates consent flow';

-- ---------------- mxid_app: CHECK constraints -----------------------------

ALTER TABLE mxid_app DROP CONSTRAINT IF EXISTS chk_app_client_type;
ALTER TABLE mxid_app ADD CONSTRAINT chk_app_client_type
    CHECK (client_type IN ('web_app','spa','native','m2m'));

-- OIDC apps: secret required for confidential (web_app/m2m), forbidden for public (spa/native).
-- Non-OIDC apps (SAML/CAS/etc) are exempt to keep migration non-breaking.
ALTER TABLE mxid_app DROP CONSTRAINT IF EXISTS chk_app_secret_presence;
ALTER TABLE mxid_app ADD CONSTRAINT chk_app_secret_presence
    CHECK (
        protocol != 'oidc'
        OR (client_type IN ('spa','native') AND client_secret IS NULL)
        OR (client_type IN ('web_app','m2m') AND client_secret IS NOT NULL)
    );

-- ---------------- mxid_app: backfill client_id for OIDC apps --------------

-- Existing OIDC rows lacking client_id receive an auto-generated value.
-- Format: client_ + 22-char base62-ish (hex-derived, sufficient for backfill uniqueness).
UPDATE mxid_app
SET client_id = 'client_' || substr(
        translate(
            encode(decode(md5(id::text || random()::text || clock_timestamp()::text), 'hex'), 'base64'),
            '+/=', 'ABC'
        ),
        1, 22
    )
WHERE protocol = 'oidc' AND client_id IS NULL;

-- ---------------- mxid_app: additional indexes ----------------------------

CREATE INDEX IF NOT EXISTS idx_app_tenant_protocol_status
    ON mxid_app(tenant_id, protocol, status) WHERE deleted_at IS NULL;

-- ---------------- mxid_app_cert: extend for OIDC signing keys -------------

ALTER TABLE mxid_app_cert
    ADD COLUMN IF NOT EXISTS kid        VARCHAR(64),
    ADD COLUMN IF NOT EXISTS not_before TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS encrypted  BOOLEAN     NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN mxid_app_cert.kid        IS 'JWKS key id exposed at /protocol/oidc/jwks';
COMMENT ON COLUMN mxid_app_cert.not_before IS 'Key activation timestamp';
COMMENT ON COLUMN mxid_app_cert.expires_at IS 'Key expiry — OIDC not_after equivalent';
COMMENT ON COLUMN mxid_app_cert.encrypted  IS 'True when private_key column stores AES-256-GCM ciphertext (base64); false for legacy plaintext';

CREATE INDEX IF NOT EXISTS idx_app_cert_app_type_status
    ON mxid_app_cert(app_id, cert_type, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_cert_kid
    ON mxid_app_cert(kid) WHERE kid IS NOT NULL;

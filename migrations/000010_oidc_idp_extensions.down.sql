-- Revert OIDC IdP Milestone A schema extensions.

DROP INDEX IF EXISTS idx_app_cert_kid;
DROP INDEX IF EXISTS idx_app_cert_app_type_status;

ALTER TABLE mxid_app_cert
    DROP COLUMN IF EXISTS encrypted,
    DROP COLUMN IF EXISTS not_before,
    DROP COLUMN IF EXISTS kid;

DROP INDEX IF EXISTS idx_app_tenant_protocol_status;

ALTER TABLE mxid_app DROP CONSTRAINT IF EXISTS chk_app_secret_presence;
ALTER TABLE mxid_app DROP CONSTRAINT IF EXISTS chk_app_client_type;

ALTER TABLE mxid_app
    DROP COLUMN IF EXISTS require_consent,
    DROP COLUMN IF EXISTS is_first_party,
    DROP COLUMN IF EXISTS home_url,
    DROP COLUMN IF EXISTS client_type;

-- Note: client_secret column type kept as VARCHAR(255) (does not break older callers).

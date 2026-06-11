-- Personal Access Tokens (PATs) for admins/users to call /openapi/v1 from
-- scripts / CI without browser session cookies. Plaintext token format:
--   mxidpat_<22-char-base32>      (32 random bytes → 26 char base32, trim
--                                  to keep total len = 30; prefix lets
--                                  secret scanners pattern-match easily)
--
-- Only the bcrypt hash + a short lookup prefix persist server-side. The
-- prefix is just the first 8 chars of the plaintext; it's not secret on
-- its own and lets the API token lookup avoid scanning all rows on every
-- request.
CREATE TABLE mxid_api_token (
    id            BIGINT PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES mxid_tenant(id),
    user_id       BIGINT NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    name          VARCHAR(128) NOT NULL,
    -- Plaintext-derived 8-char prefix used as the indexed lookup column.
    prefix        VARCHAR(16) NOT NULL,
    -- bcrypt hash of the FULL plaintext (post-prefix bytes included).
    token_hash    VARCHAR(120) NOT NULL,
    -- Scope codes the token is allowed to assert (subset of permission
    -- codes). Stored as a JSON array of strings.
    scopes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_token_user ON mxid_api_token (user_id);
CREATE INDEX idx_api_token_prefix ON mxid_api_token (prefix);

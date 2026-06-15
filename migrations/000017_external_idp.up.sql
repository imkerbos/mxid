-- External Identity Providers (Social Login + Enterprise IdP).
--
-- A single table covers the OAuth2-style providers (Lark / Feishu, GitHub,
-- Google, DingTalk, WeChat Work, ...). Each row encodes:
--   - `type`          which provider implementation handles it
--   - `code`          tenant-unique short id used in callback URLs
--   - `config`        provider-specific JSON (client_id, client_secret, scopes,
--                     api endpoints, attribute mapping, ...)
--   - `auto_create`   whether unknown subjects get a new local user
--   - `default_org_id` org to attach auto-created users to (for dept_admin scope)

CREATE TABLE IF NOT EXISTS mxid_external_idp (
    id              BIGINT PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    type            VARCHAR(32)  NOT NULL,
    name            VARCHAR(128) NOT NULL,
    code            VARCHAR(64)  NOT NULL,
    icon            VARCHAR(512),
    description     TEXT,
    config          JSONB        NOT NULL DEFAULT '{}',
    status          SMALLINT     NOT NULL DEFAULT 1, -- 1=enabled 2=disabled
    auto_create     BOOLEAN      NOT NULL DEFAULT TRUE,
    default_org_id  BIGINT,
    sort_order      INT          NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE INDEX IF NOT EXISTS idx_external_idp_type ON mxid_external_idp(tenant_id, type)
    WHERE deleted_at IS NULL;

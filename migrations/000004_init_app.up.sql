-- Application
CREATE TABLE IF NOT EXISTS mxid_app (
    id              BIGINT PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name            VARCHAR(128) NOT NULL,
    code            VARCHAR(64)  NOT NULL,
    protocol        VARCHAR(16)  NOT NULL,
    status          SMALLINT     NOT NULL DEFAULT 1,
    icon            VARCHAR(512),
    description     TEXT,
    client_id       VARCHAR(128),
    client_secret   VARCHAR(256),
    protocol_config JSONB        NOT NULL DEFAULT '{}',
    login_url       VARCHAR(512),
    redirect_uris   JSONB        DEFAULT '[]',
    logout_url      VARCHAR(512),
    access_policy   SMALLINT     NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by      BIGINT,
    updated_by      BIGINT,
    deleted_at      TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_client_id
    ON mxid_app(client_id) WHERE client_id IS NOT NULL AND deleted_at IS NULL;

-- Application group
CREATE TABLE IF NOT EXISTS mxid_app_group (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    sort_order  INT          NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

-- Application - Application group relation
CREATE TABLE IF NOT EXISTS mxid_app_group_rel (
    id          BIGINT PRIMARY KEY,
    app_id      BIGINT NOT NULL REFERENCES mxid_app(id) ON DELETE CASCADE,
    group_id    BIGINT NOT NULL REFERENCES mxid_app_group(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, group_id)
);

-- Application access authorization
CREATE TABLE IF NOT EXISTS mxid_app_access (
    id            BIGINT PRIMARY KEY,
    app_id        BIGINT       NOT NULL REFERENCES mxid_app(id) ON DELETE CASCADE,
    subject_type  VARCHAR(16)  NOT NULL,
    subject_id    BIGINT       NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by    BIGINT,
    UNIQUE(app_id, subject_type, subject_id)
);

-- Application account mapping (for form-fill)
CREATE TABLE IF NOT EXISTS mxid_app_account (
    id          BIGINT PRIMARY KEY,
    app_id      BIGINT       NOT NULL REFERENCES mxid_app(id) ON DELETE CASCADE,
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    account     VARCHAR(256) NOT NULL,
    credential  VARCHAR(512),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, user_id)
);

-- Application certificates (SAML/JWT signing)
CREATE TABLE IF NOT EXISTS mxid_app_cert (
    id             BIGINT PRIMARY KEY,
    app_id         BIGINT       NOT NULL REFERENCES mxid_app(id) ON DELETE CASCADE,
    cert_type      VARCHAR(16)  NOT NULL,
    algorithm      VARCHAR(16)  NOT NULL,
    public_key     TEXT         NOT NULL,
    private_key    TEXT         NOT NULL,
    expires_at     TIMESTAMPTZ,
    status         SMALLINT     NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

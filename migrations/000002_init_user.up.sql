-- User main table
CREATE TABLE IF NOT EXISTS mxid_user (
    id                  BIGINT PRIMARY KEY,
    tenant_id           BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    username            VARCHAR(128) NOT NULL,
    email               VARCHAR(256),
    phone               VARCHAR(32),
    display_name        VARCHAR(128),
    avatar              VARCHAR(512),
    password_hash       VARCHAR(256),
    status              SMALLINT     NOT NULL DEFAULT 1,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       VARCHAR(64),
    password_changed_at TIMESTAMPTZ,
    must_change_pwd     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by          BIGINT,
    updated_by          BIGINT,
    deleted_at          TIMESTAMPTZ,
    UNIQUE(tenant_id, username)
);

-- Conditional unique indexes for nullable columns
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_tenant_email
    ON mxid_user(tenant_id, email) WHERE email IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_tenant_phone
    ON mxid_user(tenant_id, phone) WHERE phone IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_status ON mxid_user(tenant_id, status);

-- User detail
CREATE TABLE IF NOT EXISTS mxid_user_detail (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    gender      SMALLINT,
    birthday    DATE,
    address     VARCHAR(512),
    employee_no VARCHAR(64),
    job_title   VARCHAR(128),
    department  VARCHAR(256),
    extra       JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_detail_user ON mxid_user_detail(user_id);

-- Password history
CREATE TABLE IF NOT EXISTS mxid_user_password_history (
    id            BIGINT PRIMARY KEY,
    user_id       BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    password_hash VARCHAR(256) NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pwd_history_user ON mxid_user_password_history(user_id);

-- Third-party identity binding
CREATE TABLE IF NOT EXISTS mxid_user_identity (
    id              BIGINT PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    tenant_id       BIGINT       NOT NULL,
    provider_type   VARCHAR(32)  NOT NULL,
    provider_id     VARCHAR(128) NOT NULL,
    external_id     VARCHAR(256) NOT NULL,
    external_name   VARCHAR(256),
    extra           JSONB        DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, provider_type, external_id)
);

-- MFA configuration
CREATE TABLE IF NOT EXISTS mxid_user_mfa (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    type        VARCHAR(16)  NOT NULL,
    secret      VARCHAR(256),
    config      JSONB        DEFAULT '{}',
    is_default  BOOLEAN      NOT NULL DEFAULT FALSE,
    verified    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, type)
);

-- Tenant table (MVP: single default tenant)
CREATE TABLE IF NOT EXISTS mxid_tenant (
    id          BIGINT PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL UNIQUE,
    status      SMALLINT     NOT NULL DEFAULT 1,
    config      JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

-- Seed default tenant
INSERT INTO mxid_tenant (id, name, code, status, config)
VALUES (1, 'Default', 'default', 1, '{}')
ON CONFLICT (id) DO NOTHING;

-- System settings table
CREATE TABLE IF NOT EXISTS mxid_setting (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    category    VARCHAR(64)  NOT NULL,
    key         VARCHAR(128) NOT NULL,
    value       JSONB        NOT NULL,
    description VARCHAR(256),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, category, key)
);

-- Notification records
CREATE TABLE IF NOT EXISTS mxid_notify_record (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL,
    type        VARCHAR(16)  NOT NULL,
    recipient   VARCHAR(256) NOT NULL,
    subject     VARCHAR(256),
    content     TEXT,
    status      SMALLINT     NOT NULL,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notify_tenant_time ON mxid_notify_record(tenant_id, created_at DESC);

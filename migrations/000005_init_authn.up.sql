-- Identity provider configuration (social login / enterprise IDP)
CREATE TABLE IF NOT EXISTS mxid_identity_provider (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    type        VARCHAR(32)  NOT NULL,
    category    VARCHAR(16)  NOT NULL,
    config      JSONB        NOT NULL,
    status      SMALLINT     NOT NULL DEFAULT 1,
    sort_order  INT          NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

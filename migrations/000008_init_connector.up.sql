-- Identity source connector
CREATE TABLE IF NOT EXISTS mxid_connector (
    id           BIGINT PRIMARY KEY,
    tenant_id    BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name         VARCHAR(128) NOT NULL,
    code         VARCHAR(64)  NOT NULL,
    type         VARCHAR(32)  NOT NULL,
    config       JSONB        NOT NULL,
    sync_cron    VARCHAR(64),
    status       SMALLINT     NOT NULL DEFAULT 1,
    last_sync_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

-- Connector sync log
CREATE TABLE IF NOT EXISTS mxid_connector_sync_log (
    id            BIGINT PRIMARY KEY,
    connector_id  BIGINT       NOT NULL REFERENCES mxid_connector(id) ON DELETE CASCADE,
    trigger_type  VARCHAR(16)  NOT NULL,
    status        SMALLINT     NOT NULL,
    users_created INT          DEFAULT 0,
    users_updated INT          DEFAULT 0,
    users_deleted INT          DEFAULT 0,
    orgs_created  INT          DEFAULT 0,
    orgs_updated  INT          DEFAULT 0,
    orgs_deleted  INT          DEFAULT 0,
    error_msg     TEXT,
    started_at    TIMESTAMPTZ  NOT NULL,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sync_log_connector ON mxid_connector_sync_log(connector_id, created_at DESC);

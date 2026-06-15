-- Audit log (write-only, partitioned by month)
CREATE TABLE IF NOT EXISTS mxid_audit_log (
    id              BIGINT       NOT NULL,
    tenant_id       BIGINT       NOT NULL,
    actor_id        BIGINT,
    actor_name      VARCHAR(128),
    actor_type      VARCHAR(16)  NOT NULL,
    event_type      VARCHAR(64)  NOT NULL,
    event_status    SMALLINT     NOT NULL,
    resource_type   VARCHAR(32),
    resource_id     BIGINT,
    resource_name   VARCHAR(256),
    detail          JSONB        DEFAULT '{}',
    ip              VARCHAR(64),
    user_agent      VARCHAR(512),
    geo_city        VARCHAR(64),
    geo_country     VARCHAR(64),
    session_id      VARCHAR(128),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Create partitions for current and next 3 months
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
BEGIN
    FOR i IN 0..3 LOOP
        start_date := date_trunc('month', CURRENT_DATE) + (i || ' months')::interval;
        end_date := start_date + '1 month'::interval;
        partition_name := 'mxid_audit_log_' || to_char(start_date, 'YYYY_MM');

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF mxid_audit_log
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
    END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON mxid_audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON mxid_audit_log(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event ON mxid_audit_log(event_type, created_at DESC);

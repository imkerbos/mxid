-- Per-attempt login history.
--
-- Stage distinguishes password ("first factor") from mfa ("second factor")
-- so audit can answer "was this user's password correct" independently of
-- "did they complete MFA". reason is human-readable text on failures only.
CREATE TABLE IF NOT EXISTS mxid_login_record (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    user_id     BIGINT,
    username    VARCHAR(128),
    success     BOOLEAN      NOT NULL,
    stage       VARCHAR(16)  NOT NULL DEFAULT 'password',
    auth_type   VARCHAR(32)  NOT NULL,
    reason      VARCHAR(256),
    ip          VARCHAR(64),
    user_agent  VARCHAR(512),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_record_user_time  ON mxid_login_record(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_record_tenant_time ON mxid_login_record(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_record_failed     ON mxid_login_record(success, created_at DESC) WHERE success = FALSE;

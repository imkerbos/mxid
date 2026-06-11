-- Setting key-value store.
--
-- All runtime-tunable configs live here so admins can change them without
-- a backend restart. config.yaml is reserved for bootstrap (DB DSN, Redis
-- addr, log level, KEK). Anything an operator might tweak post-deploy
-- (SMTP, password policy, branding, etc.) goes through this table.
--
-- value is JSONB so each setting can be a flat scalar OR a nested struct
-- (e.g. mail.smtp is { "host":"...", "port":587, "tls":"starttls" }).
-- Sensitive fields are AES-256 encrypted via crypto.MasterKey BEFORE
-- being serialized into the JSON — read code in internal/domain/setting/.
--
-- tenant_id: 0 = global (default), >0 = per-tenant override. Lookup
-- code reads tenant-specific first, falls back to 0 when absent.
CREATE TABLE IF NOT EXISTS mxid_setting (
    key         VARCHAR(128) NOT NULL,
    tenant_id   BIGINT       NOT NULL DEFAULT 0,
    value       JSONB        NOT NULL,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_by  BIGINT,
    PRIMARY KEY (key, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_mxid_setting_tenant ON mxid_setting(tenant_id);

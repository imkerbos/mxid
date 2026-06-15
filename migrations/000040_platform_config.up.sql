-- Platform-level configuration: deployment-wide singletons that are NOT tenant
-- data — the EE license token and the installation fingerprint UUID.
--
-- Why a dedicated table (not mxid_setting):
--   mxid_setting is tenant-scoped and fail-closed (the tenantscope gorm plugin
--   rejects any read without a tenant scope in context). But the license and the
--   install UUID are read at BOOT and BEFORE login — phases that have no tenant
--   scope — so reading them from a tenant-scoped table fails closed and the code
--   silently regenerates / downgrades. They are also platform singletons (one per
--   deployment, never per tenant), so a tenant must never be able to override
--   them. A non-tenant-scoped table fixes both: boot reads need no scope, and
--   there is no tenant_id to override.
CREATE TABLE IF NOT EXISTS mxid_platform_config (
    key        VARCHAR(128) PRIMARY KEY,
    value      JSONB        NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Move the existing platform singletons out of the tenant-scoped setting table.
-- They were stored under the default tenant; relocate them verbatim.
INSERT INTO mxid_platform_config (key, value)
SELECT key, value
FROM mxid_setting
WHERE key IN ('license', 'system.install_uuid')
ON CONFLICT (key) DO NOTHING;

DELETE FROM mxid_setting
WHERE key IN ('license', 'system.install_uuid');

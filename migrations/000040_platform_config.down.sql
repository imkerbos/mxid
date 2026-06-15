-- Roll back: move the platform singletons back into mxid_setting (as global
-- tenant_id=0 rows) and drop the dedicated table.
INSERT INTO mxid_setting (key, tenant_id, value, updated_at)
SELECT key, 0, value, updated_at
FROM mxid_platform_config
WHERE key IN ('license', 'system.install_uuid')
ON CONFLICT (key, tenant_id) DO NOTHING;

DROP TABLE IF EXISTS mxid_platform_config;

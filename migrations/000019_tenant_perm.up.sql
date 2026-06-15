-- Seed tenant.manage permission and grant to super_admin.
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (220, 1, '管理租户', 'tenant.manage', 'tenant', 'manage'),
    (221, 1, '查看租户', 'tenant.read',   'tenant', 'read')
ON CONFLICT (tenant_id, code) DO NOTHING;

INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 1220, 1, 220 ON CONFLICT DO NOTHING;
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 1221, 1, 221 ON CONFLICT DO NOTHING;

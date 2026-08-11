-- Permission for the new restore-a-deleted-user endpoint
-- (POST /api/v1/console/users/:id/restore). Its own code, not a reuse of
-- user.delete: this catalog already splits an operation from its inverse
-- into two codes (user.lock / user.unlock), and delete/restore is the same
-- shape of pair. A tenant can grant user.restore to a custom role via the
-- role UI once it decides who should be trusted to undo a deletion, without
-- also granting the ability to delete. super_admin gets it via the "*"
-- wildcard already; the explicit role_permission row below keeps the
-- catalog complete for the same reasons migration 000039's comment explains.
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (116, 1, '恢复已删除用户', 'user.restore', 'user', 'restore')
ON CONFLICT (tenant_id, code) DO NOTHING;

INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 1000 + p.id, 1, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.id = 116
ON CONFLICT (role_id, permission_id) DO NOTHING;

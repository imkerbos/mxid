-- Permission for the new super-admin toggle endpoint
-- (PUT /api/v1/console/users/:id/super-admin). Keep it separate from
-- user.update so platform owners can hand "edit my org" out without
-- accidentally letting that admin elevate themselves.
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (115, 1, '管理超级管理员', 'user.super_admin.manage', 'user', 'super_admin.manage')
ON CONFLICT (tenant_id, code) DO NOTHING;

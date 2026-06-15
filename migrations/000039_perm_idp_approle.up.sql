-- Backfill the permission catalog for modules whose console routes were
-- shipped without authz codes:
--
--   externalidp  -> idp.{create,read,update,delete}   (NEW: 240-243)
--   approle      -> app.role.manage                   (NEW: 186, fits the
--                                                       app.* block 180-185)
--
-- Already-present (verified, no new rows here):
--   audit       -> audit.read           (000016, id 200; no export route)
--   appaccess   -> app.access.manage    (000016, id 185)
--
-- super_admin (role_id=1) gets every code via mxid_user.is_super_admin at
-- runtime, but we keep its role_permission catalog complete so the Casbin
-- mirror + the privilege-escalation guard (checkAssignAllowed) see the full
-- grant set. New role_permission ids follow the 1000+p.id super_admin
-- convention from 000016/000019. auditor (role_id=4) is the global read-only
-- role, so it also receives idp.read (mirrors its *.read intent).

INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (186, 1, '管理应用角色',     'app.role.manage', 'app', 'role.manage'),

    (240, 1, '创建外部身份源',   'idp.create',      'idp', 'create'),
    (241, 1, '查看外部身份源',   'idp.read',        'idp', 'read'),
    (242, 1, '更新外部身份源',   'idp.update',      'idp', 'update'),
    (243, 1, '删除外部身份源',   'idp.delete',      'idp', 'delete')
ON CONFLICT (tenant_id, code) DO NOTHING;

-- Grant the new codes to super_admin (role_id=1).
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 1000 + p.id, 1, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.id IN (186, 240, 241, 242, 243)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- auditor (role_id=4): global read-only also covers idp.read.
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 4000 + p.id, 4, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.code = 'idp.read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

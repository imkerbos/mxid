-- Scoped admin: role bindings now carry an optional resource scope so an
-- admin role can be restricted to a single org subtree or group.
--
-- Modelling notes:
--   scope_type: 'org' | 'group' | NULL(=global)
--   scope_id:   FK-by-convention (not enforced — role can outlive scope target)
--
-- Existing global bindings keep working unchanged (scope_type = NULL).

ALTER TABLE mxid_role_binding
    ADD COLUMN IF NOT EXISTS scope_type VARCHAR(16),
    ADD COLUMN IF NOT EXISTS scope_id   BIGINT;

-- The original unique constraint only covered (role, subject) which collides
-- with the new requirement to bind the same role to the same subject at two
-- different scopes (e.g. dept_admin on org A + org B for the same user).
ALTER TABLE mxid_role_binding
    DROP CONSTRAINT IF EXISTS mxid_role_binding_role_id_subject_type_subject_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_role_binding_uniq_scoped
    ON mxid_role_binding(
        role_id,
        subject_type,
        subject_id,
        COALESCE(scope_type, ''),
        COALESCE(scope_id, 0::bigint)
    );

CREATE INDEX IF NOT EXISTS idx_role_binding_scope
    ON mxid_role_binding(scope_type, scope_id)
    WHERE scope_type IS NOT NULL;

-- ────────────────────────────────────────────────────────────────────────
-- Permission catalog (dot.case, 37 codes).
--
-- Existing colon-style permissions (console:user:read etc.) stay in the
-- table for backward compatibility but are no longer used by the new
-- authz engine. New IDs start at 100 to leave a gap above legacy 1-19.
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (100, 1, '创建用户',           'user.create',              'user', 'create'),
    (101, 1, '查看用户',           'user.read',                'user', 'read'),
    (102, 1, '更新用户',           'user.update',              'user', 'update'),
    (103, 1, '删除用户',           'user.delete',              'user', 'delete'),
    (104, 1, '锁定用户',           'user.lock',                'user', 'lock'),
    (105, 1, '解锁用户',           'user.unlock',              'user', 'unlock'),
    (106, 1, '重置用户密码',       'user.reset_password',      'user', 'reset_password'),
    (107, 1, '挂用户到部门',       'user.org.assign',          'user', 'org.assign'),
    (108, 1, '挂用户到组',         'user.group.assign',        'user', 'group.assign'),
    (109, 1, '管理用户 MFA',       'user.mfa.manage',          'user', 'mfa.manage'),
    (110, 1, '管理用户身份绑定',   'user.identity.manage',     'user', 'identity.manage'),
    (111, 1, '管理用户会话',       'user.session.manage',      'user', 'session.manage'),
    (112, 1, '查看用户登录历史',   'user.login_history.read',  'user', 'login_history.read'),

    (120, 1, '创建组织',           'org.create',               'org',  'create'),
    (121, 1, '查看组织',           'org.read',                 'org',  'read'),
    (122, 1, '更新组织',           'org.update',               'org',  'update'),
    (123, 1, '删除组织',           'org.delete',               'org',  'delete'),
    (124, 1, '添加部门成员',       'org.member.add',           'org',  'member.add'),
    (125, 1, '移除部门成员',       'org.member.remove',        'org',  'member.remove'),

    (140, 1, '创建用户组',         'group.create',             'group','create'),
    (141, 1, '查看用户组',         'group.read',               'group','read'),
    (142, 1, '更新用户组',         'group.update',             'group','update'),
    (143, 1, '删除用户组',         'group.delete',             'group','delete'),
    (144, 1, '管理组成员',         'group.member.manage',      'group','member.manage'),
    (145, 1, '管理动态组规则',     'group.rule.manage',        'group','rule.manage'),

    (160, 1, '创建角色',           'role.create',              'role', 'create'),
    (161, 1, '查看角色',           'role.read',                'role', 'read'),
    (162, 1, '更新角色',           'role.update',              'role', 'update'),
    (163, 1, '删除角色',           'role.delete',              'role', 'delete'),
    (164, 1, '分配角色',           'role.assign',              'role', 'assign'),
    (165, 1, '配置角色权限',       'role.permission.manage',   'role', 'permission.manage'),

    (180, 1, '创建应用',           'app.create',               'app',  'create'),
    (181, 1, '查看应用',           'app.read',                 'app',  'read'),
    (182, 1, '更新应用',           'app.update',               'app',  'update'),
    (183, 1, '删除应用',           'app.delete',               'app',  'delete'),
    (184, 1, '管理应用证书',       'app.cert.manage',          'app',  'cert.manage'),
    (185, 1, '管理应用访问权限',   'app.access.manage',        'app',  'access.manage'),

    (200, 1, '查看审计日志',       'audit.read',               'audit','read')
ON CONFLICT (tenant_id, code) DO NOTHING;

-- Grant all dot.case permissions to super_admin (role_id=1). Existing
-- role_permission rows for legacy colon-codes are kept.
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 1000 + p.id, 1, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.id >= 100
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ────────────────────────────────────────────────────────────────────────
-- Default scoped admin roles.
INSERT INTO mxid_role (id, tenant_id, name, code, type, description) VALUES
    (2, 1, '部门管理员',   'dept_admin',   1, '管理指定部门子树内的用户、成员关系、用户组'),
    (3, 1, '用户管理员',   'user_manager', 1, '全局用户管理（不含删除）+ 组成员维护'),
    (4, 1, '审计员',       'auditor',      1, '全局只读 + 审计日志查看'),
    (5, 1, '普通成员',     'member',       1, '仅可操作自身资料、密码、MFA')
ON CONFLICT (tenant_id, code) DO NOTHING;

-- dept_admin permission set: scope binding 时绑定到具体 org。
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 2000 + p.id, 2, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.code IN (
    'user.create','user.read','user.update',
    'user.lock','user.unlock','user.reset_password',
    'user.org.assign','user.group.assign',
    'user.mfa.manage','user.session.manage','user.login_history.read',
    'org.read','org.member.add','org.member.remove',
    'group.read','group.member.manage',
    'audit.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- user_manager: 全局，不含 delete。
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 3000 + p.id, 3, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.code IN (
    'user.create','user.read','user.update',
    'user.lock','user.unlock','user.reset_password',
    'user.org.assign','user.group.assign',
    'user.mfa.manage','user.session.manage','user.login_history.read',
    'group.read','group.member.manage'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- auditor: *.read + audit。
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT 4000 + p.id, 4, p.id
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.action = 'read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

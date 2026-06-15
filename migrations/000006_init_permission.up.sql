-- Role
CREATE TABLE IF NOT EXISTS mxid_role (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    type        SMALLINT     NOT NULL DEFAULT 1,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

-- Role binding (user/group/org → role)
CREATE TABLE IF NOT EXISTS mxid_role_binding (
    id            BIGINT PRIMARY KEY,
    role_id       BIGINT       NOT NULL REFERENCES mxid_role(id) ON DELETE CASCADE,
    subject_type  VARCHAR(16)  NOT NULL,
    subject_id    BIGINT       NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, subject_type, subject_id)
);

-- Permission definition
CREATE TABLE IF NOT EXISTS mxid_permission (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(128) NOT NULL,
    resource    VARCHAR(128) NOT NULL,
    action      VARCHAR(32)  NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, code)
);

-- Role-Permission relation
CREATE TABLE IF NOT EXISTS mxid_role_permission (
    id            BIGINT PRIMARY KEY,
    role_id       BIGINT NOT NULL REFERENCES mxid_role(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES mxid_permission(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, permission_id)
);

-- Casbin policy table (managed by Casbin GORM adapter)
CREATE TABLE IF NOT EXISTS casbin_rule (
    id    BIGSERIAL PRIMARY KEY,
    ptype VARCHAR(16),
    v0    VARCHAR(256),
    v1    VARCHAR(256),
    v2    VARCHAR(256),
    v3    VARCHAR(256),
    v4    VARCHAR(256),
    v5    VARCHAR(256)
);

-- Seed default admin role
INSERT INTO mxid_role (id, tenant_id, name, code, type, description)
VALUES (1, 1, 'Super Admin', 'super_admin', 1, 'Full system access')
ON CONFLICT (tenant_id, code) DO NOTHING;

-- Seed default permissions
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (1,  1, 'View Users',       'console:user:read',       'user',       'read'),
    (2,  1, 'Create User',      'console:user:create',     'user',       'create'),
    (3,  1, 'Update User',      'console:user:update',     'user',       'update'),
    (4,  1, 'Delete User',      'console:user:delete',     'user',       'delete'),
    (5,  1, 'View Orgs',        'console:org:read',        'org',        'read'),
    (6,  1, 'Manage Orgs',      'console:org:manage',      'org',        'manage'),
    (7,  1, 'View Apps',        'console:app:read',        'app',        'read'),
    (8,  1, 'Manage Apps',      'console:app:manage',      'app',        'manage'),
    (9,  1, 'View Roles',       'console:role:read',       'role',       'read'),
    (10, 1, 'Manage Roles',     'console:role:manage',     'role',       'manage'),
    (11, 1, 'View Audit',       'console:audit:read',      'audit',      'read'),
    (12, 1, 'Manage Settings',  'console:setting:manage',  'setting',    'manage'),
    (13, 1, 'Manage Sessions',  'console:session:manage',  'session',    'manage'),
    (14, 1, 'View Groups',      'console:group:read',      'group',      'read'),
    (15, 1, 'Manage Groups',    'console:group:manage',    'group',      'manage'),
    (16, 1, 'View Connectors',  'console:connector:read',  'connector',  'read'),
    (17, 1, 'Manage Connectors','console:connector:manage', 'connector', 'manage'),
    (18, 1, 'View IDP',         'console:idp:read',        'idp',        'read'),
    (19, 1, 'Manage IDP',       'console:idp:manage',      'idp',        'manage')
ON CONFLICT (tenant_id, code) DO NOTHING;

-- Grant all permissions to super_admin
INSERT INTO mxid_role_permission (id, role_id, permission_id)
SELECT p.id, 1, p.id FROM mxid_permission p WHERE p.tenant_id = 1
ON CONFLICT (role_id, permission_id) DO NOTHING;

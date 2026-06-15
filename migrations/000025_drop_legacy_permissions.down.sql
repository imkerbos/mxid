-- Down: re-seed legacy permissions. Idempotent via ON CONFLICT.
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
    (17, 1, 'Manage Connectors','console:connector:manage','connector',  'manage'),
    (18, 1, 'View IDP',         'console:idp:read',        'idp',        'read'),
    (19, 1, 'Manage IDP',       'console:idp:manage',      'idp',        'manage')
ON CONFLICT (tenant_id, code) DO NOTHING;

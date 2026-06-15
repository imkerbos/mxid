-- Seed default admin user (password: admin123)
INSERT INTO mxid_user (id, tenant_id, username, display_name, password_hash, status, created_at, updated_at)
VALUES (
    1,
    1,
    'admin',
    'Administrator',
    '$2a$10$L/vj.Fxj8KyX93.ANmRrMONzQBRtWwTgd/X8ZGH.XW4Nv5ATRienS',
    1,
    NOW(),
    NOW()
) ON CONFLICT (tenant_id, username) DO NOTHING;

-- Assign super_admin role to admin user
INSERT INTO mxid_role_binding (id, role_id, subject_type, subject_id, created_at)
VALUES (1, 1, 'user', 1, NOW())
ON CONFLICT (role_id, subject_type, subject_id) DO NOTHING;

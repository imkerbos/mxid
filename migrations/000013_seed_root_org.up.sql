-- Seed default root organization for the default tenant.
--
-- Every IAM deployment needs at least one organization node so the console
-- tree view, user-org assignments, and OIDC scope claims (org_id) have a
-- non-empty starting point. The root org acts as the implicit parent for
-- everything created from the UI; deleting it should be guarded at the
-- service layer (see Service.Delete).
INSERT INTO mxid_organization (id, tenant_id, name, code, parent_id, path, sort_order, status, created_at, updated_at)
VALUES (
    1,
    1,
    'MXID',
    'root',
    NULL,
    'root',
    0,
    1,
    NOW(),
    NOW()
) ON CONFLICT (tenant_id, code) DO NOTHING;

-- Attach the seeded admin user to the root org as their primary org.
INSERT INTO mxid_user_org (id, user_id, org_id, is_primary, created_at)
VALUES (1, 1, 1, TRUE, NOW())
ON CONFLICT (user_id, org_id) DO NOTHING;

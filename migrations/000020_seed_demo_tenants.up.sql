-- Demo tenants for the user's scenario. Optional — comment out or drop
-- when going to production. Kept here so a fresh dev DB shows two
-- tenants out of the box to test the multi-tenant switcher.
--
-- IDs are large enough (10/11) to not collide with the default id=1.
INSERT INTO mxid_tenant (id, name, code, status, config)
VALUES (10, 'SolidLeisure', 'solidleisure', 1, '{}'::jsonb),
       (11, 'MatrixPlus',   'matrixplus',   1, '{}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- Move the (incorrectly auto-created) Kerbos_MatrixPlus user to matrixplus tenant.
-- Safe to run repeatedly — narrow filter.
UPDATE mxid_user SET tenant_id = 11
WHERE tenant_id = 1 AND username = 'Kerbos_MatrixPlus';

-- Move Lark IdP previously configured under default to solidleisure (assuming
-- the user attached their Lark to the solidleisure organisation). Tenant
-- admin can re-route this from the UI later.
UPDATE mxid_external_idp SET tenant_id = 10
WHERE tenant_id = 1 AND code = 'lark';

-- Extend app roles + bindings to support app-group ownership.
--
-- Same model as access policy 000024:
--   - exactly one of (app_id, app_group_id) per row
--   - group-level roles + bindings cascade to every member app
--   - ResolveCodesForUser returns union of direct app + group-level
--
-- Use case: "All DevOps tools" app group defines roles infra-admin /
-- infra-viewer + binds devops user group → infra-admin. Each app in the
-- group (Grafana, Harbor, Jenkins) emits app_roles claim accordingly.

-- ─── mxid_app_role ───
ALTER TABLE mxid_app_role ALTER COLUMN app_id DROP NOT NULL;
ALTER TABLE mxid_app_role
    ADD COLUMN IF NOT EXISTS app_group_id BIGINT;
ALTER TABLE mxid_app_role
    DROP CONSTRAINT IF EXISTS chk_mxid_app_role_target;
ALTER TABLE mxid_app_role
    ADD CONSTRAINT chk_mxid_app_role_target
    CHECK (
        (app_id IS NOT NULL AND app_group_id IS NULL) OR
        (app_id IS NULL     AND app_group_id IS NOT NULL)
    );

-- Replace the (app_id, tenant_id, code) unique index with a target-agnostic one.
ALTER TABLE mxid_app_role DROP CONSTRAINT IF EXISTS mxid_app_role_app_id_tenant_id_code_key;
DROP INDEX IF EXISTS mxid_app_role_app_id_tenant_id_code_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_app_role_target_code
    ON mxid_app_role(
        COALESCE(app_id, 0),
        COALESCE(app_group_id, 0),
        tenant_id,
        code
    );
CREATE INDEX IF NOT EXISTS idx_mxid_app_role_group
    ON mxid_app_role(app_group_id, tenant_id);

-- ─── mxid_app_role_binding ───
ALTER TABLE mxid_app_role_binding ALTER COLUMN app_id DROP NOT NULL;
ALTER TABLE mxid_app_role_binding
    ADD COLUMN IF NOT EXISTS app_group_id BIGINT;
ALTER TABLE mxid_app_role_binding
    DROP CONSTRAINT IF EXISTS chk_mxid_app_role_binding_target;
ALTER TABLE mxid_app_role_binding
    ADD CONSTRAINT chk_mxid_app_role_binding_target
    CHECK (
        (app_id IS NOT NULL AND app_group_id IS NULL) OR
        (app_id IS NULL     AND app_group_id IS NOT NULL)
    );

ALTER TABLE mxid_app_role_binding DROP CONSTRAINT IF EXISTS mxid_app_role_binding_app_id_tenant_id_app_role_id_subject_t_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_app_role_binding_target_subject
    ON mxid_app_role_binding(
        COALESCE(app_id, 0),
        COALESCE(app_group_id, 0),
        tenant_id,
        app_role_id,
        subject_type,
        subject_id
    );
CREATE INDEX IF NOT EXISTS idx_mxid_app_role_binding_group
    ON mxid_app_role_binding(app_group_id, tenant_id);

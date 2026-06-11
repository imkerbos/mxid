-- App roles + bindings.
--
-- Per-application role catalog (e.g. Grafana has Admin / Editor / Viewer)
-- defined CENTRALLY in MXID. Users / groups / orgs / system roles bind
-- to one or more app_roles; at /token time MXID emits an `app_roles`
-- claim listing the role CODES that apply to the calling client.
--
-- SP simplification: instead of writing fragile JMESPath against groups,
-- the SP reads app_roles[] directly:
--     role_attribute_path = app_roles[0]
-- Multiple matches → first wins; SPs that support multi-role do nothing
-- special.
--
-- Default role: app_role with is_default=true is emitted when NO binding
-- matches the user. Covers "every authenticated user gets Viewer" without
-- needing a public binding row.

CREATE TABLE IF NOT EXISTS mxid_app_role (
    id           BIGINT       PRIMARY KEY,
    app_id       BIGINT       NOT NULL,
    tenant_id    BIGINT       NOT NULL DEFAULT 0,
    code         VARCHAR(64)  NOT NULL,
    name         VARCHAR(128) NOT NULL,
    description  TEXT,
    is_default   BOOLEAN      NOT NULL DEFAULT FALSE,
    sort_order   INT          NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by   BIGINT,
    UNIQUE (app_id, tenant_id, code)
);

CREATE INDEX IF NOT EXISTS idx_mxid_app_role_app_tenant
    ON mxid_app_role(app_id, tenant_id);

CREATE TABLE IF NOT EXISTS mxid_app_role_binding (
    id           BIGINT       PRIMARY KEY,
    app_id       BIGINT       NOT NULL,
    tenant_id    BIGINT       NOT NULL DEFAULT 0,
    app_role_id  BIGINT       NOT NULL,
    subject_type VARCHAR(16)  NOT NULL,    -- user / group / org / role
    subject_id   BIGINT       NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by   BIGINT,
    UNIQUE (app_id, tenant_id, app_role_id, subject_type, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_mxid_app_role_binding_app_subject
    ON mxid_app_role_binding(app_id, tenant_id, subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_mxid_app_role_binding_role
    ON mxid_app_role_binding(app_role_id);

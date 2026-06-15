-- Enable ltree extension for hierarchical organization tree
CREATE EXTENSION IF NOT EXISTS ltree;

-- Organization / Department
CREATE TABLE IF NOT EXISTS mxid_organization (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    parent_id   BIGINT       REFERENCES mxid_organization(id),
    path        LTREE        NOT NULL,
    sort_order  INT          NOT NULL DEFAULT 0,
    status      SMALLINT     NOT NULL DEFAULT 1,
    extra       JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by  BIGINT,
    updated_by  BIGINT,
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE INDEX IF NOT EXISTS idx_org_path ON mxid_organization USING GIST(path);
CREATE INDEX IF NOT EXISTS idx_org_parent ON mxid_organization(parent_id);
CREATE INDEX IF NOT EXISTS idx_org_tenant ON mxid_organization(tenant_id);

-- User-Organization relationship (many-to-many)
CREATE TABLE IF NOT EXISTS mxid_user_org (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT   NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    org_id      BIGINT   NOT NULL REFERENCES mxid_organization(id) ON DELETE CASCADE,
    is_primary  BOOLEAN  NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, org_id)
);

-- User groups
CREATE TABLE IF NOT EXISTS mxid_user_group (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by  BIGINT,
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

-- User group members
CREATE TABLE IF NOT EXISTS mxid_user_group_member (
    id          BIGINT PRIMARY KEY,
    group_id    BIGINT NOT NULL REFERENCES mxid_user_group(id) ON DELETE CASCADE,
    user_id     BIGINT NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, user_id)
);

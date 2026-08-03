-- Index the join tables on the column they are actually filtered by.
--
-- PostgreSQL never creates an index for a foreign key, and each of these tables
-- already has a composite unique index whose LEADING column is the other side
-- of the relation — so a lookup by the second column cannot use it and falls
-- back to a sequential scan. They looked indexed, which is why this survived.
--
--   mxid_user_group_member  UNIQUE (group_id, user_id)  filtered by user_id
--   mxid_app_group_rel      UNIQUE (app_id, group_id)   filtered by group_id
--   mxid_user_org           UNIQUE (user_id, org_id)    filtered by org_id
--   mxid_role_binding       UNIQUE leading role_id      filtered by (subject_type, subject_id)
--
-- These sit on the hottest paths in the product: every portal load resolves the
-- user's apps (appaccess/repository.go), every SSO assertion resolves app roles
-- (approle/repository.go), every authz decision resolves bindings
-- (app/adapters_authz.go), and every id_token builds the groups claim.
--
-- CONCURRENTLY is deliberately NOT used: golang-migrate runs each file in a
-- transaction, and CREATE INDEX CONCURRENTLY cannot run inside one. These
-- tables are small relative to the audit tables (membership rows, not events),
-- so the brief ACCESS SHARE lock at startup is the cheaper trade against
-- splitting the migration into a non-transactional special case.
CREATE INDEX IF NOT EXISTS idx_user_group_member_user
    ON mxid_user_group_member (user_id);

CREATE INDEX IF NOT EXISTS idx_app_group_rel_group
    ON mxid_app_group_rel (group_id);

CREATE INDEX IF NOT EXISTS idx_user_org_org
    ON mxid_user_org (org_id);

CREATE INDEX IF NOT EXISTS idx_role_binding_subject
    ON mxid_role_binding (subject_type, subject_id);

-- The console's most common audit filter is tenant + event type + a time
-- window. idx_audit_event leads with event_type and carries no tenant, so a
-- filtered query scans every partition's slice of that event type across all
-- tenants before discarding the ones that do not match.
CREATE INDEX IF NOT EXISTS idx_audit_tenant_event_time
    ON mxid_audit_log (tenant_id, event_type, created_at DESC);

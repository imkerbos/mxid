DROP INDEX IF EXISTS idx_external_idp_tenant_code;

-- Best-effort restore of the plain constraint. Fails if live+soft-deleted rows
-- now share a (tenant_id, code) pair — acceptable for a down migration.
ALTER TABLE mxid_external_idp ADD CONSTRAINT mxid_external_idp_tenant_id_code_key UNIQUE (tenant_id, code);

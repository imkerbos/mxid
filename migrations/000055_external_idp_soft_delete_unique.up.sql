-- Make (tenant_id, code) uniqueness on external IdPs soft-delete-aware, matching
-- the pattern already applied to users in 000047. The original inline
-- UNIQUE(tenant_id, code) (migration 000017) counted soft-deleted rows, so a
-- deleted IdP's code could never be reused: deleting then re-adding "lark"
-- surfaced as a raw 23505 on "create idp" while the console list (which filters
-- deleted_at IS NULL) showed nothing — a confusing "it's gone but I can't add
-- it back" state.
ALTER TABLE mxid_external_idp DROP CONSTRAINT IF EXISTS mxid_external_idp_tenant_id_code_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_external_idp_tenant_code
    ON mxid_external_idp(tenant_id, code) WHERE deleted_at IS NULL;

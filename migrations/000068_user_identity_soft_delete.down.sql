-- Restoring the total unique constraint requires physically removing the rows
-- that only the partial index tolerated.
DELETE FROM mxid_user_identity WHERE deleted_at IS NOT NULL;

DROP INDEX IF EXISTS uk_user_identity_external;

ALTER TABLE mxid_user_identity
  ADD CONSTRAINT mxid_user_identity_tenant_id_provider_type_external_id_key
  UNIQUE (tenant_id, provider_type, external_id);

DROP INDEX IF EXISTS idx_user_identity_deleted_at;
ALTER TABLE mxid_user_identity DROP COLUMN IF EXISTS deleted_at;

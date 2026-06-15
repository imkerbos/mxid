-- Add explicit super-admin flag on the user record. Replaces the legacy
-- "role_id == 1 means super admin" convention which was fragile against
-- data imports / restores that re-numbered the seed admin role.
--
-- Backfill: any user currently holding a role binding to the super_admin
-- seed role (mxid_role.code = 'super_admin') becomes is_super_admin = true.
-- After this migration the authz engine reads the column directly; the
-- role_id check at adapters_authz.go is removed in the same change.

ALTER TABLE mxid_user
    ADD COLUMN is_super_admin BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE mxid_user u
SET    is_super_admin = TRUE
WHERE  EXISTS (
    SELECT 1
    FROM   mxid_role_binding rb
    JOIN   mxid_role r ON r.id = rb.role_id
    WHERE  rb.subject_type = 'user'
      AND  rb.subject_id   = u.id
      AND  r.code          = 'super_admin'
      AND  r.deleted_at    IS NULL
);

-- Partial index for fast "is anyone super admin?" lookups, used by the
-- console to forbid deleting the last super admin in a tenant.
CREATE INDEX IF NOT EXISTS idx_mxid_user_is_super_admin
    ON mxid_user (tenant_id)
    WHERE is_super_admin IS TRUE;

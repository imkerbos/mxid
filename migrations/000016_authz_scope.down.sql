-- Revert scoped admin.
DELETE FROM mxid_role_permission WHERE id BETWEEN 1000 AND 5999;
DELETE FROM mxid_role           WHERE id BETWEEN 2 AND 5;
DELETE FROM mxid_permission     WHERE id BETWEEN 100 AND 200;

DROP INDEX IF EXISTS idx_role_binding_scope;
DROP INDEX IF EXISTS idx_role_binding_uniq_scoped;

ALTER TABLE mxid_role_binding
    DROP COLUMN IF EXISTS scope_id,
    DROP COLUMN IF EXISTS scope_type;

-- Recreate the legacy unique so down migration leaves the table consistent
-- with the previous schema. (No-op if already absent.)
ALTER TABLE mxid_role_binding
    ADD CONSTRAINT mxid_role_binding_role_id_subject_type_subject_id_key
    UNIQUE (role_id, subject_type, subject_id);

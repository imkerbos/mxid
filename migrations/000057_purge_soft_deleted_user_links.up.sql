-- Users stay soft-deleted (audit / no reactivation flow yet), but their derived
-- rows should not: a soft-deleted user otherwise lingers in every group / org /
-- role member listing and holds residual access grants. Going forward the
-- UserDeleted handler strips these; this one-time sweep clears the backlog left
-- by users soft-deleted before that handler existed. The user rows themselves
-- are kept.

BEGIN;

DELETE FROM mxid_user_group_member
 WHERE user_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NOT NULL);

DELETE FROM mxid_user_org
 WHERE user_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NOT NULL);

DELETE FROM mxid_role_binding
 WHERE subject_type = 'user'
   AND subject_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NOT NULL);

DELETE FROM mxid_app_access_policy
 WHERE subject_type = 'user'
   AND subject_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NOT NULL);

COMMIT;

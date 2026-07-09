-- Config entities (app / app_group / user_group / org / role) are HARD-deleted
-- from now on so the schema's ON DELETE CASCADE actually fires. This migration
-- (1) sweeps away rows that were previously SOFT-deleted plus every orphan they
-- stranded, and (2) adds the missing FK CASCADE on the association tables that
-- had none, so future deletes stay clean without app-level bookkeeping.
--
-- Background: soft delete (deleted_at) never triggers FK cascades, so deleting a
-- config row left its members / rels / policies alive as orphans — the root of
-- the access-policy "(未知)" and "deleted app still in its group" bugs.

BEGIN;

-- 1. Physically remove config rows that were only soft-deleted. Their ON DELETE
--    CASCADE children (app_group_rel, app_access, app_cert, app_account,
--    consents, favorites, user_group_member, user_group_rule, user_org,
--    role_binding, role_permission) are removed by the cascade.
DELETE FROM mxid_app          WHERE deleted_at IS NOT NULL;
DELETE FROM mxid_app_group    WHERE deleted_at IS NOT NULL;
DELETE FROM mxid_user_group   WHERE deleted_at IS NOT NULL;
DELETE FROM mxid_organization WHERE deleted_at IS NOT NULL;
DELETE FROM mxid_role         WHERE deleted_at IS NOT NULL;

-- 2. Purge orphan rows in tables that have NO FK (app_access_policy is fully
--    unconstrained; subject_id is polymorphic so it can never get a FK). This
--    also clears historical orphans from before hard-delete existed.
DELETE FROM mxid_app_access_policy p WHERE
     (p.app_id       IS NOT NULL AND NOT EXISTS (SELECT 1 FROM mxid_app        a WHERE a.id = p.app_id))
  OR (p.app_group_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM mxid_app_group  g WHERE g.id = p.app_group_id))
  OR (p.subject_type = 'user'  AND NOT EXISTS (SELECT 1 FROM mxid_user        u WHERE u.id = p.subject_id))
  OR (p.subject_type = 'group' AND NOT EXISTS (SELECT 1 FROM mxid_user_group  g WHERE g.id = p.subject_id))
  OR (p.subject_type = 'org'   AND NOT EXISTS (SELECT 1 FROM mxid_organization o WHERE o.id = p.subject_id))
  OR (p.subject_type = 'role'  AND NOT EXISTS (SELECT 1 FROM mxid_role        r WHERE r.id = p.subject_id));

DELETE FROM mxid_app_role         t WHERE NOT EXISTS (SELECT 1 FROM mxid_app a WHERE a.id = t.app_id);
DELETE FROM mxid_app_role_binding t WHERE NOT EXISTS (SELECT 1 FROM mxid_app a WHERE a.id = t.app_id);
DELETE FROM mxid_app_provisioning t WHERE NOT EXISTS (SELECT 1 FROM mxid_app a WHERE a.id = t.app_id);

-- 3. Add the missing FK CASCADE. (DROP IF EXISTS first keeps the migration
--    re-runnable.) subject_id gets no FK — it is polymorphic (user/group/org/
--    role) and is kept clean by the *Deleted event subscribers instead.
ALTER TABLE mxid_app_access_policy
  DROP CONSTRAINT IF EXISTS fk_app_access_policy_app,
  DROP CONSTRAINT IF EXISTS fk_app_access_policy_app_group,
  ADD  CONSTRAINT fk_app_access_policy_app       FOREIGN KEY (app_id)       REFERENCES mxid_app(id)       ON DELETE CASCADE,
  ADD  CONSTRAINT fk_app_access_policy_app_group FOREIGN KEY (app_group_id) REFERENCES mxid_app_group(id) ON DELETE CASCADE;

ALTER TABLE mxid_app_role
  DROP CONSTRAINT IF EXISTS fk_app_role_app,
  ADD  CONSTRAINT fk_app_role_app FOREIGN KEY (app_id) REFERENCES mxid_app(id) ON DELETE CASCADE;

ALTER TABLE mxid_app_role_binding
  DROP CONSTRAINT IF EXISTS fk_app_role_binding_app,
  DROP CONSTRAINT IF EXISTS fk_app_role_binding_role,
  ADD  CONSTRAINT fk_app_role_binding_app  FOREIGN KEY (app_id)      REFERENCES mxid_app(id)      ON DELETE CASCADE,
  ADD  CONSTRAINT fk_app_role_binding_role FOREIGN KEY (app_role_id) REFERENCES mxid_app_role(id) ON DELETE CASCADE;

ALTER TABLE mxid_app_provisioning
  DROP CONSTRAINT IF EXISTS fk_app_provisioning_app,
  ADD  CONSTRAINT fk_app_provisioning_app FOREIGN KEY (app_id) REFERENCES mxid_app(id) ON DELETE CASCADE;

COMMIT;

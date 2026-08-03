-- seed-demo.sql — idempotent demo fixture for the dev database.
--
-- Run via `make seed-demo`. Safe to run repeatedly: every insert is keyed on a
-- fixed id in a reserved range and ends in ON CONFLICT DO NOTHING, so re-running
-- adds nothing and destroys nothing. It never touches rows outside its ranges,
-- so your own hand-made test data survives.
--
-- Reserved id ranges (so a demo row is always recognisable, and `make
-- unseed-demo` can remove exactly these):
--   8000000000000000xx  demo users        (pre-existing; NOT created here)
--   8000000000000001xx  app groups        (pre-existing; NOT created here)
--   8000000000000002xx  apps              (pre-existing; NOT created here)
--   8000000000000003xx  app access policies
--   8000000000000004xx  user groups
--   8000000000000005xx  organizations
--   8000000000000006xx  user↔group members
--   8000000000000007xx  user↔org members
--   8000000000000008xx  app roles
--
-- The demo users (alice … nancy) and the apps are assumed to exist already.
-- What was missing — and what this file supplies — is the RELATIONSHIP data:
-- without an org, a group and an access policy, a demo user logs into the
-- portal and sees an empty app list.

BEGIN;

-- ── Organizations ────────────────────────────────────────────────────────────
-- A three-node tree under the existing root org (id 1, path 'root').
INSERT INTO mxid_organization (id, tenant_id, name, code, parent_id, path, sort_order, status, extra, created_at, updated_at, created_by)
VALUES
  (800000000000000501, 1, '技术部',   'engineering', 1, 'root.engineering', 1, 1, '{}', now(), now(), 1),
  (800000000000000502, 1, '产品部',   'product',     1, 'root.product',     2, 1, '{}', now(), now(), 1),
  (800000000000000503, 1, '运维部',   'operations',  1, 'root.operations',  3, 1, '{}', now(), now(), 1)
ON CONFLICT DO NOTHING;

-- ── User groups ──────────────────────────────────────────────────────────────
-- type 1 = static (explicit membership). Dynamic groups (type 2) are driven by
-- rules and are deliberately not seeded — they'd need mxid_user_group_rule rows
-- and a reconcile pass to look right.
INSERT INTO mxid_user_group (id, tenant_id, name, code, description, type, created_at, updated_at, created_by)
VALUES
  (800000000000000401, 1, '研发',     'developers', '研发工程师,可访问研发工具', 1, now(), now(), 1),
  (800000000000000402, 1, '运维',     'sre',        '运维/SRE,可访问运维平台',   1, now(), now(), 1),
  (800000000000000403, 1, '全体员工', 'all-staff',  '所有在职员工',              1, now(), now(), 1)
ON CONFLICT DO NOTHING;

-- ── Org membership ───────────────────────────────────────────────────────────
-- alice/bob/carol → 技术部, dave/eve → 产品部, frank/grace → 运维部,
-- the rest land in the root org so nobody is orphaned.
INSERT INTO mxid_user_org (id, user_id, org_id, is_primary, created_at)
VALUES
  (800000000000000701, 800000000000000001, 800000000000000501, true, now()),
  (800000000000000702, 800000000000000002, 800000000000000501, true, now()),
  (800000000000000703, 800000000000000003, 800000000000000501, true, now()),
  (800000000000000704, 800000000000000004, 800000000000000502, true, now()),
  (800000000000000705, 800000000000000005, 800000000000000502, true, now()),
  (800000000000000706, 800000000000000006, 800000000000000503, true, now()),
  (800000000000000707, 800000000000000007, 800000000000000503, true, now()),
  (800000000000000708, 800000000000000008, 1,                  true, now()),
  (800000000000000709, 800000000000000009, 1,                  true, now()),
  (800000000000000710, 800000000000000010, 1,                  true, now()),
  (800000000000000711, 800000000000000011, 1,                  true, now()),
  (800000000000000712, 800000000000000012, 1,                  true, now())
ON CONFLICT DO NOTHING;

-- ── Group membership ─────────────────────────────────────────────────────────
-- Everyone joins all-staff; engineering joins developers; ops joins sre.
INSERT INTO mxid_user_group_member (id, group_id, user_id, created_at)
SELECT 800000000000000600 + row_number() OVER (ORDER BY u.id), 800000000000000403, u.id, now()
FROM mxid_user u
WHERE u.id BETWEEN 800000000000000001 AND 800000000000000012
ON CONFLICT DO NOTHING;

INSERT INTO mxid_user_group_member (id, group_id, user_id, created_at)
VALUES
  (800000000000000651, 800000000000000401, 800000000000000001, now()),
  (800000000000000652, 800000000000000401, 800000000000000002, now()),
  (800000000000000653, 800000000000000401, 800000000000000003, now()),
  (800000000000000661, 800000000000000402, 800000000000000006, now()),
  (800000000000000662, 800000000000000402, 800000000000000007, now())
ON CONFLICT DO NOTHING;

-- ── Repair: drop the orphaned access policy ──────────────────────────────────
-- Policy 800000000000000303 grants access to "group 800000000000000103", but
-- that id belongs to an APP group, not a user group — the original ad-hoc seed
-- crossed the two id ranges. A subject that resolves to nothing renders as
-- "未知" in the console, so remove it; the all-staff grant below replaces it.
DELETE FROM mxid_app_access_policy
WHERE id = 800000000000000303
  AND subject_type = 'group'
  AND NOT EXISTS (SELECT 1 FROM mxid_user_group g WHERE g.id = mxid_app_access_policy.subject_id);

-- Same class of bug, generalised: any policy whose group subject no longer
-- resolves. Scoped to the demo id range so real data is never touched.
DELETE FROM mxid_app_access_policy p
WHERE p.id BETWEEN 800000000000000300 AND 800000000000000399
  AND p.subject_type = 'group'
  AND NOT EXISTS (SELECT 1 FROM mxid_user_group g WHERE g.id = p.subject_id);

-- ── App access ───────────────────────────────────────────────────────────────
-- The point of the whole file: give the demo users something to SEE.
-- all-staff → every app group, so each demo user's portal is populated.
INSERT INTO mxid_app_access_policy (id, app_id, tenant_id, subject_type, subject_id, effect, created_at, created_by, app_group_id)
VALUES
  (800000000000000321, NULL, 1, 'group', 800000000000000403, 'allow', now(), 1, 800000000000000101),
  (800000000000000322, NULL, 1, 'group', 800000000000000403, 'allow', now(), 1, 800000000000000102),
  -- ops platform stays restricted to the sre group — so the console shows a
  -- meaningful contrast between a broad grant and a narrow one.
  (800000000000000323, NULL, 1, 'group', 800000000000000402, 'allow', now(), 1, 800000000000000103),
  -- finance is deliberately left ungranted: an app group nobody can reach is
  -- useful for testing the "no access" path.
  (800000000000000324, NULL, 1, 'group', 800000000000000401, 'allow', now(), 1, 800000000000000101)
ON CONFLICT DO NOTHING;

-- ── App roles ────────────────────────────────────────────────────────────────
-- Two roles per app group, so the `app_roles` claim has something to carry and
-- the role-mapping UI isn't empty.
INSERT INTO mxid_app_role (id, app_id, tenant_id, code, name, description, is_default, sort_order, created_at, created_by, app_group_id)
VALUES
  (800000000000000801, NULL, 1, 'admin',  '管理员', '完整管理权限',   false, 1, now(), 1, 800000000000000101),
  (800000000000000802, NULL, 1, 'viewer', '只读',   '只读访问',       true,  2, now(), 1, 800000000000000101),
  (800000000000000803, NULL, 1, 'admin',  '管理员', '完整管理权限',   false, 1, now(), 1, 800000000000000102),
  (800000000000000804, NULL, 1, 'viewer', '只读',   '只读访问',       true,  2, now(), 1, 800000000000000102),
  (800000000000000805, NULL, 1, 'sre',    'SRE',    '运维平台操作权限', false, 1, now(), 1, 800000000000000103),
  (800000000000000806, NULL, 1, 'viewer', '只读',   '只读访问',       true,  2, now(), 1, 800000000000000103)
ON CONFLICT DO NOTHING;

COMMIT;

-- ── Summary ──────────────────────────────────────────────────────────────────
\echo ''
\echo 'seed-demo: current state'
SELECT 'organizations'   AS entity, count(*) AS rows FROM mxid_organization
UNION ALL SELECT 'user groups',        count(*) FROM mxid_user_group
UNION ALL SELECT 'group members',      count(*) FROM mxid_user_group_member
UNION ALL SELECT 'org members',        count(*) FROM mxid_user_org
UNION ALL SELECT 'app access policies',count(*) FROM mxid_app_access_policy
UNION ALL SELECT 'app roles',          count(*) FROM mxid_app_role
UNION ALL SELECT 'orphan policies',    count(*) FROM mxid_app_access_policy p
    WHERE p.subject_type = 'group'
      AND NOT EXISTS (SELECT 1 FROM mxid_user_group g WHERE g.id = p.subject_id);

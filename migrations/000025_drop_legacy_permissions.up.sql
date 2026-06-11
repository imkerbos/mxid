-- Drop legacy colon-style permissions (console:*) seeded in 000006.
--
-- They were superseded by the dot-style codes (user.read / app.read / ...)
-- introduced in 000016 and never referenced by the active authz engine.
-- super_admin uses a wildcard `*` so removing these rows does NOT affect
-- access for the default role.
--
-- Run order: 000006 seeds 1-19 → 000016 seeds 100-200 → this migration
-- removes 1-19 + their orphan role_permission rows.

DELETE FROM mxid_role_permission WHERE permission_id BETWEEN 1 AND 19;
DELETE FROM mxid_permission WHERE id BETWEEN 1 AND 19;

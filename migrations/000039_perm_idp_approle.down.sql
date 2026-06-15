-- Reverse 000039: drop the role_permission grants then the permission rows.
DELETE FROM mxid_role_permission WHERE permission_id IN (186, 240, 241, 242, 243);
DELETE FROM mxid_permission WHERE id IN (186, 240, 241, 242, 243);

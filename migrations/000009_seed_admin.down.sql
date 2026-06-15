DELETE FROM mxid_role_binding WHERE subject_type = 'user' AND subject_id = 1 AND role_id = 1;
DELETE FROM mxid_user WHERE id = 1 AND username = 'admin';

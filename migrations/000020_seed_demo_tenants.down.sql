UPDATE mxid_external_idp SET tenant_id = 1 WHERE tenant_id = 10 AND code = 'lark';
UPDATE mxid_user SET tenant_id = 1 WHERE tenant_id = 11 AND username = 'Kerbos_MatrixPlus';
DELETE FROM mxid_tenant WHERE id IN (10, 11);

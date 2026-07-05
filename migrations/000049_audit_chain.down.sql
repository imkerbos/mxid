-- migrations/000049_audit_chain.down.sql
DROP TABLE IF EXISTS mxid_audit_chain_head;
DROP TABLE IF EXISTS mxid_audit_entry;
DROP TABLE IF EXISTS mxid_audit_pending;

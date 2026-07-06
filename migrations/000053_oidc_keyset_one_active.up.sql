-- Enforce at most one ACTIVE (status=1) signing key. Without this, two replicas
-- racing key rotation could leave two simultaneously-active keys, so JWKS/kid
-- selection would disagree pod-to-pod. The keyset is a single global issuer
-- keyset (no tenant/provider scope), so a bare partial unique index on status
-- gives "at most one row where status=1".

-- Upgrade safety: reconcile any pre-existing multiple-active rows BEFORE creating
-- the index, so an upgrade over dirty data heals instead of failing the migration.
-- The old Rotate was Generate-then-demote and NOT transactional, so a crash
-- between the two steps — or a prior multi-replica run — could persist more than
-- one status=active row. Keep the newest active as the signer and demote the rest
-- to ROTATING (status=2; still published in JWKS, verify-only) — exactly the end
-- state a clean rotation produces. golang-migrate wraps this file in a single
-- transaction, so the reconcile + index build apply atomically.
UPDATE mxid_oidc_keyset SET status = 2
WHERE status = 1
  AND id NOT IN (
    SELECT id FROM mxid_oidc_keyset
    WHERE status = 1
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  );

CREATE UNIQUE INDEX IF NOT EXISTS uq_oidc_keyset_one_active
    ON mxid_oidc_keyset (status)
    WHERE status = 1;

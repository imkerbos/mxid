-- Identity bindings were hard-deleted, so an admin mis-click on "unbind" was
-- irreversible and left the user unable to sign in through their external IdP.
ALTER TABLE mxid_user_identity ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_user_identity_deleted_at ON mxid_user_identity (deleted_at);

-- The unique key must become partial in the same step. A soft-deleted row would
-- otherwise keep occupying (tenant_id, provider_type, external_id) and every
-- re-bind would collide with a row nobody can see. The constraint is declared
-- inline in 000002, so its name is Postgres-generated — look it up rather than
-- betting on the generated name. The lookup is narrowed to a unique constraint
-- whose column set is exactly {tenant_id, provider_type, external_id} (order
-- independent), so it can never match some other unique constraint the table
-- might gain later; if more than one such constraint somehow exists, it raises
-- instead of picking one non-deterministically.
DO $$
DECLARE
  cname TEXT;
  match_count INT;
  target_attnums SMALLINT[];
BEGIN
  SELECT array_agg(a.attnum ORDER BY a.attnum)
  INTO target_attnums
  FROM pg_attribute a
  WHERE a.attrelid = 'mxid_user_identity'::regclass
    AND a.attname IN ('tenant_id', 'provider_type', 'external_id');

  SELECT count(*), max(c.conname)
  INTO match_count, cname
  FROM pg_constraint c
  WHERE c.conrelid = 'mxid_user_identity'::regclass
    AND c.contype = 'u'
    AND (SELECT array_agg(k ORDER BY k) FROM unnest(c.conkey) AS k) = target_attnums;

  IF match_count > 1 THEN
    RAISE EXCEPTION 'multiple unique constraints found on mxid_user_identity(tenant_id, provider_type, external_id); refusing to drop non-deterministically';
  ELSIF match_count = 1 THEN
    EXECUTE format('ALTER TABLE mxid_user_identity DROP CONSTRAINT %I', cname);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uk_user_identity_external
  ON mxid_user_identity (tenant_id, provider_type, external_id)
  WHERE deleted_at IS NULL;
